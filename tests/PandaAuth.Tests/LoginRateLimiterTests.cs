using Xunit;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Tests;

public class LoginRateLimiterTests : IDisposable
{
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());

    private readonly LoginRateLimiter _limiter;

    public LoginRateLimiterTests()
    {
        _limiter = new LoginRateLimiter(_cache, Options.Create(new AuthOptions
        {
            RateLimit = new RateLimitOptions
            {
                IpPerMinute = 3,
                AccountPerMinute = 2,
            },
        }));
    }

    [Fact]
    public void Account_OverLimit_IsRejected()
    {
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.False(_limiter.AttemptByAccount("user-a").IsAcquired);
    }

    [Fact]
    public void Accounts_AreLimitedIndependently()
    {
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.False(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-b").IsAcquired);
    }

    [Fact]
    public void AccountKey_IsCaseInsensitive()
    {
        Assert.True(_limiter.AttemptByAccount("User-A").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-A").IsAcquired);
        Assert.False(_limiter.AttemptByAccount("USER-a").IsAcquired);
    }

    [Fact]
    public void Ip_OverLimit_IsRejected()
    {
        Assert.True(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
        Assert.True(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
        Assert.True(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
        Assert.False(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
    }

    [Fact]
    public void MissingIp_FallsBackToSharedBucket()
    {
        Assert.True(_limiter.AttemptByIp(null).IsAcquired);
        Assert.True(_limiter.AttemptByIp(null).IsAcquired);
        Assert.True(_limiter.AttemptByIp(null).IsAcquired);
        Assert.False(_limiter.AttemptByIp(null).IsAcquired);
    }

    [Fact]
    public void EntryTimeToLive_ExceedsFixedWindow()
    {
        // TTL 必须大于固定窗口：否则窗口未结束条目就被回收，计数被重置，限流被静默削弱。
        Assert.True(LoginRateLimiter.DefaultEntryTimeToLive > TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task Entries_AreReclaimed_AndWindowResets_AfterTimeToLive()
    {
        // 短 TTL：条目过期后应被回收（而不是像早先的 ConcurrentDictionary 那样只增不删）。
        // 固定窗口仍是 1 分钟，条目若未被回收则同一账号在窗口内必然继续被拒——这正是本用例的判别力所在。
        var (cache, limiter) = CreateWithTimeToLive(ShortTimeToLive, accountPerMinute: 2);
        using var _ = cache;
        using var __ = limiter;

        Assert.True(limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.False(limiter.AttemptByAccount("user-a").IsAcquired);

        await Task.Delay(TimeSpan.FromMilliseconds(400));

        Assert.True(limiter.AttemptByAccount("user-a").IsAcquired, "超过 TTL 的条目应被回收，窗口计数随之重置。");
    }

    [Fact]
    public async Task WithinEntryTimeToLive_WindowIsNotReset()
    {
        // 与上一条互为对照：TTL 未到时绝不能回收，否则窗口计数被重置、限流被静默削弱。
        var (cache, limiter) = CreateWithTimeToLive(TimeSpan.FromHours(1), accountPerMinute: 2);
        using var _ = cache;
        using var __ = limiter;

        Assert.True(limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(limiter.AttemptByAccount("user-a").IsAcquired);

        await Task.Delay(TimeSpan.FromMilliseconds(400));

        Assert.False(limiter.AttemptByAccount("user-a").IsAcquired);
    }

    [Fact]
    public async Task ExpiredEntries_ArePhysicallyRemoved_SoCacheDoesNotGrowWithVisitedKeys()
    {
        var (cache, limiter) = CreateWithTimeToLive(ShortTimeToLive, accountPerMinute: 2);
        using var _ = cache;
        using var __ = limiter;

        // 变换用户名撑大字典是评审指出的攻击面：每个 key 都应随 TTL 回收。
        for (var index = 0; index < 10; index++)
        {
            limiter.AttemptByAccount($"user-{index}");
        }

        Assert.Equal(10, cache.Count);

        await Task.Delay(TimeSpan.FromMilliseconds(400));

        // 只对 trigger 发起请求（不再触碰那 10 个 key）：MemoryCache 没有空闲回收定时器，
        // 未被触碰的过期条目要靠缓存活动触发的扫描物理移除（已实测），真实流量下同样由后续登录请求触发。
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (cache.Count > 1 && DateTime.UtcNow < deadline)
        {
            limiter.AttemptByAccount("trigger");
            await Task.Delay(50);
        }

        Assert.True(cache.Count <= 1, $"超期条目应被物理移除，实际仍有 {cache.Count} 条。");
    }

    [Fact]
    public void ConcurrentColdStart_DoesNotAmplifyPermits()
    {
        // 并发冷启动回归：同一 key 首次出现（缓存未命中）时，大量并发请求若各自新建 limiter，
        // 每个实例都带满额许可，单次突发会被放行到并发数倍。用真线程 + 屏障同时释放最大化该竞争；
        // 每轮换新 key（等价于冷启动），避免命中路径掩盖缺陷。
        const int concurrency = 64;
        const int rounds = 20;
        using var cache = new MemoryCache(new MemoryCacheOptions());
        using var limiter = new LoginRateLimiter(cache, Options.Create(new AuthOptions
        {
            RateLimit = new RateLimitOptions { AccountPerMinute = 1 },
        }));

        var worst = 0;
        for (var round = 0; round < rounds; round++)
        {
            var key = $"cold-start-account-{round}";
            var barrier = new Barrier(concurrency);
            var acquired = 0;
            var threads = new Thread[concurrency];

            for (var index = 0; index < concurrency; index++)
            {
                threads[index] = new Thread(() =>
                {
                    barrier.SignalAndWait();
                    if (limiter.AttemptByAccount(key).IsAcquired)
                    {
                        Interlocked.Increment(ref acquired);
                    }
                });
                threads[index].Start();
            }

            foreach (var thread in threads)
            {
                thread.Join();
            }

            Assert.True(
                acquired <= 1,
                $"第 {round} 轮冷启动突发（{concurrency} 并发、许可 1）放行了 {acquired} 次，超过许可数。");
            worst = Math.Max(worst, acquired);
        }

        // 同时必须有请求真的拿到许可，否则说明限流器把正常请求一并拒了。
        Assert.Equal(1, worst);
    }

    [Fact]
    public void Dispose_ReleasesTrackedLimiters_SoQuotaIsNotReusedFromDisposedInstances()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new LoginRateLimiter(cache, Options.Create(new AuthOptions
        {
            RateLimit = new RateLimitOptions { AccountPerMinute = 1 },
        }));

        Assert.True(limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.False(limiter.AttemptByAccount("user-a").IsAcquired);

        limiter.Dispose();

        // 释放后条目重建：若 Dispose 只置位而不清理，这里会命中已释放的 limiter（拒绝或抛异常）。
        Assert.True(limiter.AttemptByAccount("user-a").IsAcquired);
    }

    private static readonly TimeSpan ShortTimeToLive = TimeSpan.FromMilliseconds(200);

    private static (MemoryCache Cache, LoginRateLimiter Limiter) CreateWithTimeToLive(
        TimeSpan timeToLive, int accountPerMinute)
    {
        var cache = new MemoryCache(new MemoryCacheOptions
        {
            // 让过期扫描足够频繁，使依赖扫描的用例（物理回收）不必等待默认的 1 分钟扫描周期。
            ExpirationScanFrequency = TimeSpan.FromMilliseconds(25),
        });
        var limiter = new LoginRateLimiter(
            cache,
            Options.Create(new AuthOptions
            {
                RateLimit = new RateLimitOptions { AccountPerMinute = accountPerMinute },
            }),
            timeToLive);
        return (cache, limiter);
    }

    public void Dispose()
    {
        _limiter.Dispose();
        _cache.Dispose();
    }
}
