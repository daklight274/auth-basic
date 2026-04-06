using Auth.Application.IServices;
using Auth.Application.Services;
using Auth.Application.Settings;
using Auth.Domain.Entities;
using Auth.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using Serilog.Events;
using StackExchange.Redis;
using System.Text;
using static Auth.API.Controllers.AuthController;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting AuthService...");

    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, services, cfg) => cfg
        .ReadFrom.Configuration(ctx.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .WriteTo.Console(outputTemplate:
            "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
        .WriteTo.File(
            path: "logs/auth-.log",
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 30,
            outputTemplate:
                "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] " +
                "{Message:lj} {Properties:j}{NewLine}{Exception}")
    );

    builder.Services.AddDbContext<AppDbContext>(opts =>
        opts.UseSqlServer(builder.Configuration.GetConnectionString("Default")));

    // ── Redis ──────────────────────────────────────────────────────────────────────
    builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
        ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")!));

    // Smtp
    builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));

    var jwtSection = builder.Configuration.GetSection("Jwt");
    builder.Services.Configure<JwtSettings>(jwtSection);
    var jwtCfg = jwtSection.Get<JwtSettings>()!;

    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(opts =>
        {
            opts.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(jwtCfg.SecretKey)),
                ValidateIssuer = true,
                ValidIssuer = jwtCfg.Issuer,
                ValidateAudience = true,
                ValidAudience = jwtCfg.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
            };
            opts.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = ctx =>
                {
                    var logger = ctx.HttpContext.RequestServices
                        .GetRequiredService<ILogger<Program>>();
                    logger.LogWarning("JWT authentication failed: {Error}",
                        ctx.Exception.Message);
                    return Task.CompletedTask;
                }
            };
        });

    builder.Services.AddAuthorization();

    builder.Services.AddScoped<IJwtService, JwtService>();
    builder.Services.AddScoped<IAuthService, AuthService>();
    builder.Services.AddScoped<IEmailService, EmailService>();
    builder.Services.AddScoped<IRedisService, RedisService>();

    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();

    builder.Services.AddSwaggerGen(opts =>
    {
        opts.SwaggerDoc("v1", new OpenApiInfo
        {
            Title = "AuthService API",
            Version = "v1",
            Description = "JWT Authentication — Register, Login, Protected endpoints",
        });

        opts.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Nhập access token. Ví dụ: eyJhbGci...",
        });

        opts.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id   = "Bearer",
                    }
                },
                Array.Empty<string>()
            }
        });
    });

    builder.Services.AddAuthorization(opt =>
    {
        opt.AddPolicy("AdminOnly", p => p.RequireRole(User.Names.Admin));
        opt.AddPolicy("UserOnly", p => p.RequireRole(User.Names.User));
    });

    var app = builder.Build();

    app.UseSerilogRequestLogging(opts =>
    {
        opts.MessageTemplate =
            "HTTP {RequestMethod} {RequestPath} → {StatusCode} ({Elapsed:0.0}ms)";
        opts.GetLevel = (ctx, _, ex) =>
            ex != null || ctx.Response.StatusCode >= 500 ? LogEventLevel.Error :
            ctx.Response.StatusCode >= 400 ? LogEventLevel.Warning :
                                                           LogEventLevel.Information;
    });

    app.UseMiddleware<ExceptionMiddleware>();

    app.UseSwagger();
    app.UseSwaggerUI(opts =>
    {
        opts.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthService v1");
        opts.RoutePrefix = "swagger";  // truy cập tại https://localhost:7171/swagger
        opts.DisplayRequestDuration();
        opts.DefaultModelsExpandDepth(-1);
    });

    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    app.Run();
}
catch (Exception ex)
    when (ex is not HostAbortedException          // EF Tools tự tắt app — bỏ qua
       && ex.GetType().Name != "StopTheHostException")
{
    Log.Fatal(ex, "AuthService terminated unexpectedly.");
}
finally
{
    Log.CloseAndFlush();
}