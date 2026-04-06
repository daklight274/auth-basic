using Auth.Application.IServices;
using Microsoft.EntityFrameworkCore.Storage;
using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IDatabase = StackExchange.Redis.IDatabase;

namespace Auth.Application.Services
{
    public class RedisService : IRedisService
    {
        private readonly IConnectionMultiplexer _redis;
        public RedisService(IConnectionMultiplexer redis) => _redis = redis;
        private IDatabase Db => _redis.GetDatabase();

        public async Task SetAsync(string key, string value, TimeSpan? expiry = null)
        {
            if (expiry.HasValue)
                await Db.StringSetAsync(key, value, expiry.Value);
            else
                await Db.StringSetAsync(key, value);
        }

        public async Task<string?> GetAsync(string key)
        {
            var value = await Db.StringGetAsync(key);
            return value.IsNullOrEmpty ? null : value.ToString();
        }

        public async Task DeleteAsync(string key)
            => await Db.KeyDeleteAsync(key);

        public async Task<bool> ExistsAsync(string key)
            => await Db.KeyExistsAsync(key);
    }
}
