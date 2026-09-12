using System.Collections.Concurrent;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// 登录接口限流：IP 与账号双维度固定窗口（内存实现，单实例架构下满足需求）。
/// P3 集群化时替换为 Redis 分布式实现，调用方不变。
/// </summary>
public sealed class LoginRateLimiter : IDisposable
{
    private readonly ConcurrentDictionary<string, FixedWindowRateLimiter> _ipLimiters = new();
    private readonly ConcurrentDictionary<string, FixedWindowRateLimiter> _accountLimiters = new();
    private readonly RateLimitOptions _options;

    public LoginRateLimiter(IOptions<AuthOptions> options)
    {
        _options = options.Value.RateLimit;
    }

    public RateLimitLease AttemptByIp(string? ipAddress)
    {
        var key = string.IsNullOrWhiteSpace(ipAddress) ? "unknown" : ipAddress!;
        return Acquire(_ipLimiters, key, _options.IpPerMinute);
    }

    public RateLimitLease AttemptByAccount(string userName)
    {
        var key = userName.Trim().ToLowerInvariant();
        return Acquire(_accountLimiters, key, _options.AccountPerMinute);
    }

    private static RateLimitLease Acquire(
        ConcurrentDictionary<string, FixedWindowRateLimiter> cache, string key, int permitsPerMinute)
    {
        var limiter = cache.GetOrAdd(key, static (_, limit) => new FixedWindowRateLimiter(
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = limit,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }), permitsPerMinute);
        return limiter.AttemptAcquire();
    }

    public void Dispose()
    {
        foreach (var limiter in _ipLimiters.Values)
        {
            limiter.Dispose();
        }

        foreach (var limiter in _accountLimiters.Values)
        {
            limiter.Dispose();
        }
    }
}
