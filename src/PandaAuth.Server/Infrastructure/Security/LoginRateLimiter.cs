using System.Threading.RateLimiting;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// 登录接口限流：IP 与账号双维度固定窗口（内存实现，单实例架构下满足需求）。
/// P3 集群化时替换为 Redis 分布式实现，调用方不变。
/// </summary>
/// <remarks>
/// 限流器条目承载在 <see cref="IMemoryCache"/> 上并按 TTL 回收（机械见
/// <see cref="FixedWindowLimiterCache"/>，与 ManagementRateLimiter 共用），取代早先两个只增不删的
/// ConcurrentDictionary——后者下每个出现过的 IP/用户名都会常驻一个 limiter，
/// 在变换用户名（或伪造 IP，已收敛但仍是输入）的组合下可被低成本撑大内存。
/// TTL（默认 2 分钟）严格大于固定窗口（1 分钟），保证窗口未结束前条目不会被回收而重置计数。
/// </remarks>
public sealed class LoginRateLimiter : IDisposable
{
    private static readonly string IpKeyPrefix = "login-ratelimit:ip:";
    private static readonly string AccountKeyPrefix = "login-ratelimit:account:";

    /// <summary>条目 TTL = 窗口时长 + 余量（保持原内部常量引用，测试断言依赖）。</summary>
    internal static readonly TimeSpan DefaultEntryTimeToLive = FixedWindowLimiterCache.DefaultEntryTimeToLive;

    private readonly FixedWindowLimiterCache _limiterCache;
    private readonly RateLimitOptions _options;

    public LoginRateLimiter(IMemoryCache cache, IOptions<AuthOptions> options)
        : this(cache, options, FixedWindowLimiterCache.DefaultEntryTimeToLive)
    {
    }

    /// <summary>测试用：注入短 TTL 以断言回收行为。</summary>
    internal LoginRateLimiter(IMemoryCache cache, IOptions<AuthOptions> options, TimeSpan entryTimeToLive)
    {
        _options = options.Value.RateLimit;
        _limiterCache = new FixedWindowLimiterCache(cache, entryTimeToLive);
    }

    public RateLimitLease AttemptByIp(string? ipAddress)
        => _limiterCache.Acquire(IpCacheKey(ipAddress), _options.IpPerMinute);

    public RateLimitLease AttemptByAccount(string userName)
        => _limiterCache.Acquire(AccountCacheKey(userName), _options.AccountPerMinute);

    internal static string IpCacheKey(string? ipAddress)
        => IpKeyPrefix + (string.IsNullOrWhiteSpace(ipAddress) ? "unknown" : ipAddress);

    internal static string AccountCacheKey(string userName)
        => AccountKeyPrefix + userName.Trim().ToLowerInvariant();

    public void Dispose() => _limiterCache.Dispose();
}
