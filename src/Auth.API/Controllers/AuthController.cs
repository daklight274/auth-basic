using Auth.Application.DTOs;
using Auth.Application.IServices;
using Auth.Application.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using static Auth.Application.Services.AuthService;

namespace Auth.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest req)
        {
            var result = await _authService.RegisterAsync(req, GetIpAddress());
            //SetRefreshTokenCookie(result.RefreshToken);
            return StatusCode(201, result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest req)
        {
            var result = await _authService.LoginAsync(req, GetIpAddress());
            SetRefreshTokenCookie(result.RefreshToken);
            return Ok(ToSafeResponse(result));
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            // Đọc refresh token từ HttpOnly cookie — JS không thể đọc cookie này
            var token = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(token))
                return Unauthorized(new { error = "Refresh token not found." });

            var result = await _authService.RefreshTokenAsync(token, GetIpAddress());
            SetRefreshTokenCookie(result.RefreshToken);
            return Ok(ToSafeResponse(result));
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var token = Request.Cookies["refreshToken"];
            if (!string.IsNullOrEmpty(token))
                await _authService.RevokeTokenAsync(token, GetIpAddress());

            // Xóa cookie
            Response.Cookies.Delete("refreshToken");
            return Ok(new { message = "Logged out." });
        }

        // Endpoint demo [Authorize] — trả về thông tin từ JWT claims
        [HttpGet("user/me")]
        [Authorize]
        public IActionResult UserMe()
        {
            // ClaimsPrincipal được populate bởi JWT middleware sau khi verify token
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                      ?? User.FindFirst("sub")?.Value;
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                     ?? User.FindFirst(ClaimTypes.Email)?.Value;
            var role = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            return Ok(new { userId, email, role });
        }

        [HttpGet("admin/me")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminMe()
        {
            // ClaimsPrincipal được populate bởi JWT middleware sau khi verify token
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                      ?? User.FindFirst("sub")?.Value;
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                     ?? User.FindFirst(ClaimTypes.Email)?.Value;
            var role = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            return Ok(new { userId, email, role });
        }

        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequestDto dto)
        {
            var result = await _authService.VerifyEmailAsync(dto,GetIpAddress());
            SetRefreshTokenCookie(result.RefreshToken);
            return StatusCode(200, ToSafeResponse(result));
        }


        // ── HELPERS ──────────────────────────────────────────────────

        // Gắn refresh token vào HttpOnly cookie
        // HttpOnly = JS không đọc được → chống XSS
        // Secure   = chỉ gửi qua HTTPS
        // SameSite = Strict → chống CSRF
        private void SetRefreshTokenCookie(string token)
        {
            Response.Cookies.Append("refreshToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(7),
            });
        }

        // Không bao giờ trả refresh token trong JSON body
        private static object ToSafeResponse(AuthResponse r) => new
        {
            r.AccessToken,
            r.TokenType,
            r.ExpiresIn,
            r.User,
        };

        private string GetIpAddress() =>
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // ──────────────────────────────────────────────
        // Global Exception Handler Middleware
        // ──────────────────────────────────────────────
        public class ExceptionMiddleware(RequestDelegate next, ILogger<ExceptionMiddleware> logger)
        {
            public async Task InvokeAsync(HttpContext ctx)
            {
                try
                {
                    await next(ctx);
                }
                catch (ConflictException ex)
                {
                    logger.LogWarning("409 Conflict: {Message}", ex.Message);
                    ctx.Response.StatusCode = 409;
                    await ctx.Response.WriteAsJsonAsync(new { error = ex.Message });
                }
                catch (UnauthorizedException ex)
                {
                    logger.LogWarning("401 Unauthorized: {Message}", ex.Message);
                    ctx.Response.StatusCode = 401;
                    await ctx.Response.WriteAsJsonAsync(new { error = ex.Message });
                }
                catch (Exception ex)
                {
                    // Log Error với full stack trace — chỉ log 500 ở đây
                    logger.LogError(ex, "500 Unhandled exception on {Method} {Path}",
                        ctx.Request.Method, ctx.Request.Path);
                    ctx.Response.StatusCode = 500;
                    await ctx.Response.WriteAsJsonAsync(new { error = "Internal server error" });
                }
            }
        }
    }
}
