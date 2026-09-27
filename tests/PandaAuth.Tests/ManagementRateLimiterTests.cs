using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Features.Management;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// Management API 限流（M0 S4）：read/write/secret 三桶、clientId+IP 双维判定与冷启动并发回归。
/// 机械（TTL 回收、按值匹配回收、确定性释放）由 LoginRateLimiterTests 在共享的
/// FixedWindowLimiterCache 上覆盖，此处不重复。
/// </summary>
public class ManagementRateLimiterTests : IDisposable
{
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());

    [Fact]
    public void Read_OverLimit_IsRejected_WithRetryAfter()
    {
        using var limiter = TestsMgmtLimiter.New(new MgmtRateLimitOptions { ReadPerMinute = 2 });

        Assert.True(limiter.CheckRead("app-a", "203.0.113.1").Allowed);
        Assert.True(limiter.CheckRead("app-a", "203.0.113.1").Allowed);

        var rejected = limiter.CheckRead("app-a", "203.0.113.1");
        Assert.False(rejected.Allowed);
        Assert.InRange(rejected.RetryAfterSeconds, 1, 60);
    }

    [Fact]
    public void ClientAndIp_DimensionsAreIndependent()
    {
        using var limiter = TestsMgmtLimiter.New(new MgmtRateLimitOptions { ReadPerMinute = 1 });

        // clientId 维共享：同一 clientId 换 IP 仍共享其 1 次许可
        // （被拒路径会按设计消耗已获取维度的许可——部分消耗不回滚，见 Check 的注释）。
        Assert.True(limiter.CheckRead("app-a", "203.0.113.1").Allowed);
        Assert.False(limiter.CheckRead("app-a", "203.0.113.2").Allowed);

        // IP 维共享：换 clientId 用已耗尽的 IP 仍被拒。
        Assert.False(limiter.CheckRead("app-b", "203.0.113.1").Allowed);

        // 双维都干净的组合放行。
        Assert.True(limiter.CheckRead("app-b", "203.0.113.3").Allowed);
    }

    [Fact]
    public void Write_And_Secret_Buckets_AreIndependent()
    {
        using var limiter = TestsMgmtLimiter.New(new MgmtRateLimitOptions
        {
            WritePerMinute = 5,
            SecretPerMinute = 1,
        });

        // 秘钥桶只放 1 次；写桶仍有余量但 secret:ip 已越限 → 拒。
        Assert.True(limiter.CheckSecret("app-a", "203.0.113.1").Allowed);
        Assert.False(limiter.CheckSecret("app-a", "203.0.113.1").Allowed);

        // 普通写不受 secret 桶影响。
        Assert.True(limiter.CheckWrite("app-a", "203.0.113.1").Allowed);
    }

    [Fact]
    public void SecretCheck_FailsFast_WhenIpBucketExhausted_BeforeWriteDimensions()
    {
        // 先把 write:ip 打满，再验证 secret:ip 严格桶先拒（IP 维先于 client 维）。
        using var limiter = TestsMgmtLimiter.New(new MgmtRateLimitOptions
        {
            WritePerMinute = 1,
            SecretPerMinute = 10,
        });

        Assert.True(limiter.CheckWrite("app-a", "203.0.113.1").Allowed);
        Assert.False(limiter.CheckWrite("app-a", "203.0.113.1").Allowed);
        // secret 依赖 write:ip（已耗尽）→ 拒，无论 secret 桶余量。
        Assert.False(limiter.CheckSecret("app-b", "203.0.113.1").Allowed);
    }

    [Fact]
    public void ClientKey_IsCaseInsensitive_AndMissingFallsBackToSharedBucket()
    {
        using var limiter = TestsMgmtLimiter.New(new MgmtRateLimitOptions { ReadPerMinute = 1 });

        Assert.True(limiter.CheckRead("App-A", "203.0.113.1").Allowed);
        Assert.False(limiter.CheckRead("app-a", "203.0.113.1").Allowed);

        // clientId 缺失（理论上被授权策略挡住）共享 unknown 桶。
        Assert.True(limiter.CheckRead(null, "203.0.113.9").Allowed);
        Assert.False(limiter.CheckRead(null, "203.0.113.9").Allowed);
    }

    [Fact]
    public void ConcurrentColdStart_DoesNotAmplifyPermits()
    {
        // 与 LoginRateLimiterTests 同款冷启动回归：同一 key 首次出现的并发突发不得放大许可。
        const int concurrency = 64;
        const int rounds = 10;
        using var limiter = TestsMgmtLimiter.New(new MgmtRateLimitOptions { ReadPerMinute = 1 });

        var worst = 0;
        for (var round = 0; round < rounds; round++)
        {
            var ip = $"198.51.100.{round}";
            var barrier = new Barrier(concurrency);
            var acquired = 0;
            var threads = new Thread[concurrency];

            for (var index = 0; index < concurrency; index++)
            {
                threads[index] = new Thread(() =>
                {
                    barrier.SignalAndWait();
                    if (limiter.CheckRead("app-cold", ip).Allowed)
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

            Assert.True(acquired <= 1, $"第 {round} 轮冷启动突发放行了 {acquired} 次，超过许可数。");
            worst = Math.Max(worst, acquired);
        }

        Assert.Equal(1, worst);
    }

    public void Dispose() => _cache.Dispose();
}
