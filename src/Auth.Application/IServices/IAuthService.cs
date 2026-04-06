using Auth.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Application.IServices
{
    public interface IAuthService
    {
        Task<string> RegisterAsync(RegisterRequest req, string ipAddress);
        Task<AuthResponse> LoginAsync(LoginRequest req, string ipAddress);
        Task<AuthResponse> RefreshTokenAsync(string token, string ipAddress);
        Task RevokeTokenAsync(string token, string ipAddress);
        Task<AuthResponse> VerifyEmailAsync(VerifyEmailRequestDto dto,string ip);
    }
}
