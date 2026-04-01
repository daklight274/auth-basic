using Auth.Application.DTOs;
using Auth.Application.IServices;
using Auth.Application.Settings;
using Auth.Domain.Entities;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Application.Services
{
    public class AuthService:IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IJwtService _jwtService;
        private readonly ILogger<AuthService> _logger;
        private readonly JwtSettings _jwt;

        public AuthService(AppDbContext context, IJwtService jwtService,ILogger<AuthService> logger,IOptions<JwtSettings> jwt)
        {
            _context = context;
            _jwtService = jwtService;
            _logger = logger;
            _jwt = jwt.Value;
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest req, string ipAddress)
        {
            var email = req.Email.ToLower();

            _logger.LogInformation("Register attempt for {Email}", email);
            // 1. Check duplicate email (case-insensitive)
            var exists = await _context.Users
                .AnyAsync(u => u.Email.ToLower() == email);

            if (exists)
            {
                _logger.LogWarning("Register failed — duplicate email {Email}", email);
                throw new ConflictException("Email already registered.");
            }

            // 2. Hash password
            // BCrypt tự embed salt vào hash string → không cần lưu salt riêng
            // WorkFactor 12 ≈ ~250ms/hash — đủ chậm để brute-force không hiệu quả
            var hash = BCrypt.Net.BCrypt.HashPassword(req.Password, workFactor: 12);

            // 3. Persist
            var user = new User
            {
                Email = req.Email.ToLower(),
                PasswordHash = hash,
                FullName = req.FullName,
                Role = "User",
            };

            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            // KHÔNG log password, hash, hay bất kỳ sensitive data nào
            _logger.LogInformation(
                "Register success — UserId={UserId} Email={Email}",
                user.Id, user.Email);
            // 4. Return token ngay (hoặc bắt verify email trước — Giai đoạn 3)
            return await BuildAuthResponseAsync(user, ipAddress);
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest req, string ipAddress)
        {
            var email = req.Email.ToLower();

            _logger.LogInformation("Login attempt for {Email}", email);
            // 1. Lookup user — KHÔNG tiết lộ "email không tồn tại" vs "sai password"
            //    → luôn trả về cùng lỗi 401 để tránh user enumeration
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email);

            // 2. Verify password
            // BCrypt.Verify tự extract salt từ hash, hash lại input và so sánh
            // KHÔNG hash rồi so sánh bằng == (timing attack!)
            var valid = user is not null
                        && BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash);

            if (!valid)
            {
                // Log Warning — không tiết lộ nguyên nhân cụ thể
                _logger.LogWarning(
                    "Login failed — invalid credentials for {Email}", email);
                throw new UnauthorizedException("Invalid credentials.");
            }

            _logger.LogInformation(
                "Login success — UserId={UserId} Email={Email} Role={Role}",
                user!.Id, user.Email, user.Role);

            return await BuildAuthResponseAsync(user, ipAddress);
        }

        public async Task<AuthResponse> RefreshTokenAsync(string token, string ipAddress)
        {
            var existing = await _context.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == token);

            if (existing is null)
                throw new UnauthorizedException("Invalid refresh token.");

            // === REUSE DETECTION ===
            // Nếu token đã bị revoke → có thể bị đánh cắp và dùng lại
            // → revoke toàn bộ token của user (nuclear option)
            if (existing.IsRevoked)
            {
                _logger.LogWarning(
                    "Refresh token reuse detected! UserId={UserId} Token={Token}",
                    existing.UserId, token[..8]);

                await RevokeAllUserTokensAsync(existing.UserId, ipAddress, "Reuse detected");
                throw new UnauthorizedException("Refresh token reuse detected.");
            }

            if (existing.IsExpired)
                throw new UnauthorizedException("Refresh token expired.");

            // === TOKEN ROTATION ===
            // Revoke token cũ, tạo token mới
            var newRefresh = GenerateRefreshToken(ipAddress);
            existing.RevokedAt = DateTime.UtcNow;
            existing.ReplacedByToken = newRefresh.Token;

            newRefresh.UserId = existing.UserId;
            await _context.RefreshTokens.AddAsync(newRefresh);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Token rotated UserId={UserId}", existing.UserId);

            return new AuthResponse
            {
                AccessToken = _jwtService.GenerateToken(existing.User),
                TokenType = "Bearer",
                ExpiresIn = _jwtService.ExpiresInSeconds,
                RefreshToken = newRefresh.Token,
                User = new UserInfo
                {
                    Id = existing.User.Id,
                    Email = existing.User.Email,
                    FullName = existing.User.FullName,
                    Role = existing.User.Role
                }
            };
        }

        public async Task RevokeTokenAsync(string token, string ipAddress)
        {
            var existing = await _context.RefreshTokens
            .FirstOrDefaultAsync(r => r.Token == token);

            if (existing is null || !existing.IsActive)
                throw new UnauthorizedException("Invalid or already revoked token.");

            existing.RevokedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            _logger.LogInformation("Token revoked UserId={UserId}", existing.UserId);
        }

        // ── HELPERS ──────────────────────────────────────────────────
        private async Task<AuthResponse> BuildAuthResponseAsync(User user, string ip)
        {
            var accessToken = _jwtService.GenerateToken(user);
            var refreshToken = GenerateRefreshToken(ip);
            refreshToken.UserId = user.Id;

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return new AuthResponse {
                AccessToken = accessToken,
                TokenType = "Bearer",
                ExpiresIn = _jwtService.ExpiresInSeconds,
                RefreshToken = refreshToken.Token,
                User = new UserInfo
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Role = user.Role
                }
            };

        }
        private RefreshToken GenerateRefreshToken(string ip) => new()
        {
            // 64 bytes random → base64 → 88 ký tự, không đoán được
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            ExpiresAt = DateTime.UtcNow.AddDays(_jwt.RefreshTokenExpiryDays),
            CreatedByIp = ip,
        };

        private async Task RevokeAllUserTokensAsync(string userId, string ip, string reason)
        {
            var tokens = await _context.RefreshTokens
                .Where(r => r.UserId == userId && r.RevokedAt == null)
                .ToListAsync();

            foreach (var t in tokens)
                t.RevokedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            _logger.LogWarning("Revoked all tokens for UserId={UserId} Reason={Reason}", userId, reason);
        }

        // Custom exceptions → tương ứng HTTP status code
        public class ConflictException(string msg) : Exception(msg);
        public class UnauthorizedException(string msg) : Exception(msg);
    }
}
