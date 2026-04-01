using Auth.Application.IServices;
using Auth.Application.Settings;
using Auth.Domain.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Application.Services
{
    public class JwtService(IOptions<JwtSettings> jwt) :IJwtService
    {
        private readonly JwtSettings _jwt = jwt.Value;
        public int ExpiresInSeconds => _jwt.ExpiresInMinutes * 60;

        public string GenerateToken(User user)
        {
            // === CLAIMS: payload của JWT ===
            // "sub"   = subject, định danh duy nhất của user (RFC 7519)
            // "email" = custom claim, không phải chuẩn nhưng rất thông dụng
            // "role"  = dùng cho authorization sau này
            // "jti"   = JWT ID, unique per token — dùng để revoke nếu cần
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub,   user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role,               user.Role),
        };

            // === SIGNING KEY ===
            // HS256 = HMAC-SHA256: symmetric key, cùng key để sign và verify
            // Chỉ dùng trong internal service. Public API nên dùng RS256 (asymmetric)
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // === TOKEN DESCRIPTOR ===
            var token = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                // exp = thời điểm token hết hạn — LUÔN dùng UTC
                expires: DateTime.UtcNow.AddMinutes(_jwt.ExpiresInMinutes),
                signingCredentials: creds
            );

            // Serialize → "xxxxx.yyyyy.zzzzz" (header.payload.signature)
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
