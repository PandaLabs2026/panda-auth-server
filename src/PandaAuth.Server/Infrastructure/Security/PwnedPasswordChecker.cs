using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;

namespace PandaAuth.Server.Infrastructure.Security;

public enum PwnedPasswordOutcome
{
    /// <summary>未检测：功能未启用或没有可检查的密码。</summary>
    NotChecked,

    /// <summary>已检测，未出现在已知泄露库。</summary>
    Clean,

    /// <summary>已检测，出现在已知泄露库。</summary>
    Breached,

    /// <summary>未能完成检测（网络/超时/非 200）——按 Auth:Hibp:FailClosed 解释。</summary>
    ServiceUnavailable,
}

/// <summary>检测结果与是否应拒绝的最终判定（决策在检测器内按配置算好，调用方不再解释）。</summary>
public sealed record PwnedPasswordDecision(bool Rejected, PwnedPasswordOutcome Outcome);

public interface IPwnedPasswordChecker
{
    Task<PwnedPasswordDecision> CheckAsync(string? password, CancellationToken cancellationToken = default);
}

/// <summary>
/// 泄露密码检测（HIBP k-anonymity）：只外呼 SHA1 前 5 位（prefix model），后缀本地比对，
/// 密码原文与完整哈希都不出站。结果缓存：命中泄露 7 天、干净 1 小时（限制内存增长）。
/// 故障语义见 HibpOptions（默认失败开放）；登录路径检测下一迭代接入，当前只覆盖设置密码路径。
/// </summary>
public sealed class PwnedPasswordChecker : IPwnedPasswordChecker
{
    internal static readonly TimeSpan BreachedCacheTtl = TimeSpan.FromDays(7);
    internal static readonly TimeSpan CleanCacheTtl = TimeSpan.FromHours(1);

    private const string CachePrefix = "hibp:";

    private readonly HttpClient httpClient;
    private readonly HibpOptions options;
    private readonly IMemoryCache cache;
    private readonly ILogger<PwnedPasswordChecker> logger;

    public PwnedPasswordChecker(
        HttpClient httpClient,
        IOptions<AuthOptions> options,
        IMemoryCache cache,
        ILogger<PwnedPasswordChecker> logger)
    {
        this.httpClient = httpClient;
        this.options = options.Value.Hibp;
        this.cache = cache;
        this.logger = logger;
    }

    public async Task<PwnedPasswordDecision> CheckAsync(string? password, CancellationToken cancellationToken = default)
    {
        if (!options.Enabled || string.IsNullOrEmpty(password))
        {
            return new PwnedPasswordDecision(false, PwnedPasswordOutcome.NotChecked);
        }

        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        if (cache.TryGetValue($"{CachePrefix}{hash}", out PwnedPasswordOutcome cached))
        {
            return Decide(cached);
        }

        PwnedPasswordOutcome outcome;
        try
        {
            using var response = await httpClient.GetAsync(
                $"{options.ApiBase.TrimEnd('/')}/range/{hash[..5]}",
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"HIBP range 端点返回 {(int)response.StatusCode}。");
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            var suffix = hash[5..];
            outcome = body.Split('\n').Any(line => line.Trim().StartsWith(suffix, StringComparison.Ordinal))
                ? PwnedPasswordOutcome.Breached
                : PwnedPasswordOutcome.Clean;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // 调用方主动取消：原样上抛，不算服务故障。
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            // 网络故障/超时/非 200：按部署方选择的失败策略记录并返回，不抛出。
            logger.LogWarning(exception, "HIBP 查询失败，按{Policy}处理。", options.FailClosed ? "失败关闭" : "失败开放");
            return Decide(PwnedPasswordOutcome.ServiceUnavailable);
        }

        cache.Set(
            $"{CachePrefix}{hash}",
            outcome,
            outcome == PwnedPasswordOutcome.Breached ? BreachedCacheTtl : CleanCacheTtl);
        return Decide(outcome);
    }

    private PwnedPasswordDecision Decide(PwnedPasswordOutcome outcome)
        => new(
            outcome switch
            {
                PwnedPasswordOutcome.Breached => true,
                PwnedPasswordOutcome.ServiceUnavailable => options.FailClosed,
                _ => false,
            },
            outcome);
}
