using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Management;

/// <summary>
/// Management API 限流：clientId 与 IP 双维固定窗口（内存实现，单实例架构下满足需求；
/// P3 集群化时与登录限流一同替换为 Redis 实现，调用方不变）。
/// 桶：read（读端点）、write（写端点）、secret（密钥端点的额外按 IP 严格许可，防枚举）。
/// 机械（TTL 回收、冷启动串行化、确定性释放）与 LoginRateLimiter 共用 FixedWindowLimiterCache。
/// </summary>
public sealed class ManagementRateLimiter : IDisposable
{
    /// <summary>限流判定：Allowed=false 时 RetryAfterSeconds 为各被拒维度中的最大等待秒数。</summary>
    public sealed record Decision(bool Allowed, int RetryAfterSeconds)
    {
        public static readonly Decision Acquired = new(true, 0);
    }

    private readonly FixedWindowLimiterCache _limiterCache;
    private readonly MgmtRateLimitOptions _options;

    public ManagementRateLimiter(IMemoryCache cache, IOptions<AuthOptions> options)
        : this(cache, options.Value.Mgmt.RateLimit)
    {
    }

    /// <summary>测试用：直接注入桶配置。</summary>
    internal ManagementRateLimiter(IMemoryCache cache, MgmtRateLimitOptions options)
    {
        _limiterCache = new FixedWindowLimiterCache(cache);
        _options = options;
    }

    /// <summary>读端点：clientId + IP 双维。</summary>
    public Decision CheckRead(string? clientId, string? ip)
        => Check(
            ("read:ip", IpKey(ip), _options.ReadPerMinute),
            ("read:client", ClientKey(clientId), _options.ReadPerMinute));

    /// <summary>写端点：clientId + IP 双维。</summary>
    public Decision CheckWrite(string? clientId, string? ip)
        => Check(
            ("write:ip", IpKey(ip), _options.WritePerMinute),
            ("write:client", ClientKey(clientId), _options.WritePerMinute));

    /// <summary>密钥端点：IP 严格桶（创建/重置共享，防枚举）先判，再走写双维。</summary>
    public Decision CheckSecret(string? clientId, string? ip)
        => Check(
            ("secret:ip", IpKey(ip), _options.SecretPerMinute),
            ("write:ip", IpKey(ip), _options.WritePerMinute),
            ("write:client", ClientKey(clientId), _options.WritePerMinute));

    /// <summary>
    /// 多维顺序判定：IP 维先于 client 维（请求方先烧自己的 IP 配额，而非消耗被叫客户端的许可）；
    /// 任一维被拒即快速失败（不再消耗后续维度的许可）。部分消耗不回滚——被拒即请求方已越限，
    /// 少量许可损耗换取免锁实现。
    /// </summary>
    private Decision Check(params (string Prefix, string Key, int Permits)[] dimensions)
    {
        TimeSpan? retryAfter = null;
        foreach (var (prefix, key, permits) in dimensions)
        {
            using var lease = _limiterCache.Acquire($"mgmt-ratelimit:{prefix}:{key}", Math.Max(1, permits));
            if (lease.IsAcquired)
            {
                continue;
            }

            // 取被拒维度中最大的 Retry-After（各维固定窗口的起点可能不同）。
            if (lease.TryGetMetadata(MetadataName.RetryAfter, out var span)
                && (!retryAfter.HasValue || span > retryAfter.Value))
            {
                retryAfter = span;
            }

            break;
        }

        return retryAfter is null
            ? Decision.Acquired
            : new Decision(false, Math.Max(1, (int)Math.Ceiling(retryAfter.Value.TotalSeconds)));
    }

    internal static string ClientKey(string? clientId)
        => string.IsNullOrWhiteSpace(clientId) ? "unknown" : clientId.Trim().ToLowerInvariant();

    internal static string IpKey(string? ip)
        => string.IsNullOrWhiteSpace(ip) ? "unknown" : ip;

    public void Dispose() => _limiterCache.Dispose();
}

/// <summary>调用方在主体上的 clientId 取值（M2M 令牌经验证后携带 client_id claim）。</summary>
public static class ManagementRateLimiterPrincipals
{
    public static string GetClientId(System.Security.Claims.ClaimsPrincipal principal)
        => principal.FindFirst(Claims.ClientId)?.Value ?? "unknown";
}

internal static class ManagementRateLimitResults
{
    /// <summary>429 + Retry-After（RFC 6585 / 7231）；ProblemDetails 语义与站内其余错误面一致。</summary>
    public static IActionResult TooManyRequests(this ControllerBase controller, ManagementRateLimiter.Decision decision)
    {
        controller.Response.Headers.RetryAfter = decision.RetryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        return controller.Problem(
            statusCode: StatusCodes.Status429TooManyRequests,
            title: "请求过于频繁",
            detail: "Management API 触发速率限制，请按 Retry-After 头稍后重试。");
    }
}
