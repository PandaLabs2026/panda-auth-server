using System.Collections.Concurrent;
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
/// 限流器条目承载在 <see cref="IMemoryCache"/> 上并按 TTL 回收，取代早先两个只增不删的
/// <see cref="ConcurrentDictionary{TKey,TValue}"/>——后者下每个出现过的 IP/用户名都会常驻一个 limiter，
/// 在变换用户名（或伪造 IP，已收敛但仍是输入）的组合下可被低成本撑大内存。
/// TTL（默认 2 分钟）严格大于固定窗口（1 分钟），保证窗口未结束前条目不会被回收而重置计数。
/// </remarks>
public sealed class LoginRateLimiter : IDisposable
{
    /// <summary>固定窗口时长。</summary>
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    /// <summary>条目 TTL = 窗口时长 + 余量。</summary>
    internal static readonly TimeSpan DefaultEntryTimeToLive = TimeSpan.FromMinutes(2);

    private static readonly string IpKeyPrefix = "login-ratelimit:ip:";
    private static readonly string AccountKeyPrefix = "login-ratelimit:account:";

    private readonly IMemoryCache _cache;
    private readonly RateLimitOptions _options;
    private readonly TimeSpan _entryTimeToLive;

    /// <summary>
    /// 活动条目镜像：仅用于让 <see cref="Dispose"/> 能确定性释放 limiter。
    /// 条目随缓存回收一并移除，因此与缓存同为有界。
    /// </summary>
    private readonly ConcurrentDictionary<string, FixedWindowRateLimiter> _live = new();

    /// <summary>
    /// 未命中路径的串行化锁（临界区只做「建 limiter + 写缓存」，无 I/O）。
    /// 冷启动时同一 key 的并发请求会同时未命中，若各自建实例就等于把许可放大到并发数倍；
    /// 锁内二次检查保证同一 key 同时只有一个 limiter 对外服务。命中路径不加锁。
    /// </summary>
    private readonly Lock _resolveLock = new();

    public LoginRateLimiter(IMemoryCache cache, IOptions<AuthOptions> options)
        : this(cache, options, DefaultEntryTimeToLive)
    {
    }

    /// <summary>测试用：注入短 TTL 以断言回收行为。</summary>
    internal LoginRateLimiter(IMemoryCache cache, IOptions<AuthOptions> options, TimeSpan entryTimeToLive)
    {
        _cache = cache;
        _options = options.Value.RateLimit;
        _entryTimeToLive = entryTimeToLive;
    }

    public RateLimitLease AttemptByIp(string? ipAddress)
        => Acquire(IpCacheKey(ipAddress), _options.IpPerMinute);

    public RateLimitLease AttemptByAccount(string userName)
        => Acquire(AccountCacheKey(userName), _options.AccountPerMinute);

    internal static string IpCacheKey(string? ipAddress)
        => IpKeyPrefix + (string.IsNullOrWhiteSpace(ipAddress) ? "unknown" : ipAddress);

    internal static string AccountCacheKey(string userName)
        => AccountKeyPrefix + userName.Trim().ToLowerInvariant();

    private RateLimitLease Acquire(string key, int permitsPerMinute)
    {
        // 缓存条目即 limiter 的存活凭据：条目在则 limiter 一定未被回收（可以安全使用），
        // 条目不在（不存在或已过期）则旧 limiter 已进入回收流程，必须重建，不能复用。
        for (var attempt = 0; ; attempt++)
        {
            var limiter = Resolve(key, permitsPerMinute);
            try
            {
                return limiter.AttemptAcquire();
            }
            catch (ObjectDisposedException) when (attempt == 0)
            {
                // 实测：MemoryCache 的回收回调异步派发——条目被移除与 limiter 被释放之间存在窗口，
                // 恰好落在窗口内的请求会拿到已释放的 limiter（其 AttemptAcquire 抛 ObjectDisposedException）。
                // 重试一次即可：此时缓存必然未命中，会重建 limiter。
            }
        }
    }

    private FixedWindowRateLimiter Resolve(string key, int permitsPerMinute)
    {
        // 快路径：命中缓存，拿到的即该 key 当前唯一的 limiter 实例。
        if (_cache.TryGetValue(key, out var cached) && cached is FixedWindowRateLimiter cachedLimiter)
        {
            return cachedLimiter;
        }

        // 慢路径：冷启动（或条目刚过期）时并发请求会同时未命中。必须串行化并二次检查，
        // 否则每个并发请求都会 new 出一个带满额许可的 limiter（后写覆盖先写，先写的实例仍被调用方使用），
        // 等效把许可放大到并发数倍。旧实现用 ConcurrentDictionary.GetOrAdd 天然避免了这一点，
        // 改为内存缓存后必须显式补回同一语义。
        lock (_resolveLock)
        {
            if (_cache.TryGetValue(key, out var raced) && raced is FixedWindowRateLimiter racedLimiter)
            {
                return racedLimiter;
            }

            var limiter = new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitsPerMinute,
                Window = Window,
                QueueLimit = 0,
            });

            // 覆盖镜像中可能残留的旧实例：旧实例的回收回调按值匹配移除，不匹配则不做任何事，
            // 因此不会误删或误释放这个新实例。
            _live[key] = limiter;
            _cache.Set(key, limiter, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _entryTimeToLive,
            }.RegisterPostEvictionCallback(OnEntryEvicted, key));

            return limiter;
        }
    }

    /// <summary>
    /// 条目被回收时释放其 limiter。实测两条行为决定了这里的写法：
    /// 回调是异步派发的（条目先被移除、回调稍后执行）；被替换的条目必须按值匹配，
    /// 否则会误删/误释放接管了同一 key 的新实例。
    /// </summary>
    private void OnEntryEvicted(object key, object? value, EvictionReason reason, object? state)
    {
        if (reason == EvictionReason.Replaced ||
            key is not string cacheKey ||
            value is not FixedWindowRateLimiter limiter)
        {
            return;
        }

        if (_live.TryRemove(new KeyValuePair<string, FixedWindowRateLimiter>(cacheKey, limiter)))
        {
            limiter.Dispose();
        }
    }

    public void Dispose()
    {
        // 不释放注入的 IMemoryCache（由容器持有、可能被其它消费者共享）：
        // 实测 MemoryCache.Dispose() 既不回收条目也不触发回收回调，所以这里逐条清理自己登记的条目。
        // 先按值从镜像摘除再撤条目，回收回调随后按值匹配时不会再命中，避免重复释放。
        foreach (var (key, limiter) in _live)
        {
            if (_live.TryRemove(new KeyValuePair<string, FixedWindowRateLimiter>(key, limiter)))
            {
                _cache.Remove(key);
                limiter.Dispose();
            }
        }
    }
}
