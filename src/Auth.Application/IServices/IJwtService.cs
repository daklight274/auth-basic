using Auth.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Application.IServices
{
    public interface IJwtService
    {
        string GenerateToken(User user);
        int ExpiresInSeconds { get; }
    }
}
