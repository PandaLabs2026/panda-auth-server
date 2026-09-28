using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 泄露密码检测（HIBP k-anonymity）单元测试：前缀外呼契约、后缀本地比对、
/// 缓存行为与失败策略（默认失败开放）。HttpMessageHandler 桩替代真实外呼。
/// </summary>
public class PwnedPasswordCheckerTests : IDisposable
{
    private readonly MemoryCache cache = new(new MemoryCacheOptions());

    private sealed class StubHandler : HttpMessageHandler
    {
        public int Calls;

        public string? LastPrefix;

        public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } =
            _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(string.Empty) };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            LastPrefix = request.RequestUri!.AbsolutePath.Split('/').LastOrDefault();
            return Task.FromResult(Responder(request));
        }
    }

    private (PwnedPasswordChecker Checker, StubHandler Handler) Create(HibpOptions? hibp = null)
    {
        var options = hibp ?? new HibpOptions { Enabled = true };
        var handler = new StubHandler();
        var checker = new PwnedPasswordChecker(
            new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(options.TimeoutMs) },
            Options.Create(new AuthOptions { Hibp = options }),
            cache,
            NullLogger<PwnedPasswordChecker>.Instance);
        return (checker, handler);
    }

    private static string Sha1(string password)
        => Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));

    private static string RangeBody(string password, bool include)
    {
        // 构造 HIBP range 响应：若干条 "SUFFIX:COUNT" 行；include 决定是否含目标后缀。
        var hash = Sha1(password);
        var lines = new List<string> { "00000004", "ABCDEF011" };
        if (include)
        {
            lines.Add($"{hash[5..]}:23");
        }

        return string.Join("\r\n", lines);
    }

    [Fact]
    public async Task Disabled_ReturnsNotChecked_WithoutOutboundCall()
    {
        var (checker, handler) = Create(new HibpOptions { Enabled = false });

        var decision = await checker.CheckAsync("Whatever!2026");

        Assert.False(decision.Rejected);
        Assert.Equal(PwnedPasswordOutcome.NotChecked, decision.Outcome);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task BreachedPassword_IsRejected_AndOnlyPrefixIsSent()
    {
        var password = "Breached!2026";
        var (checker, handler) = Create();
        handler.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(RangeBody(password, include: true)),
        };

        var decision = await checker.CheckAsync(password);

        Assert.True(decision.Rejected);
        Assert.Equal(PwnedPasswordOutcome.Breached, decision.Outcome);
        // k-anonymity：只外呼 SHA1 前 5 位，且为大写十六进制。
        Assert.Equal(Sha1(password)[..5], handler.LastPrefix);
        Assert.Equal(5, handler.LastPrefix!.Length);
    }

    [Fact]
    public async Task CleanPassword_Passes()
    {
        var password = "CleanPass!2026";
        var (checker, handler) = Create();
        handler.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(RangeBody(password, include: false)),
        };

        var decision = await checker.CheckAsync(password);

        Assert.False(decision.Rejected);
        Assert.Equal(PwnedPasswordOutcome.Clean, decision.Outcome);
    }

    [Fact]
    public async Task Results_AreCached_SecondCallDoesNotHitNetwork()
    {
        var password = "Cached!2026";
        var (checker, handler) = Create();
        handler.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(RangeBody(password, include: true)),
        };

        var first = await checker.CheckAsync(password);
        var second = await checker.CheckAsync(password);

        Assert.True(first.Rejected);
        Assert.True(second.Rejected);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task ServiceFailure_DefaultFailOpen_ReturnsServiceUnavailable_WithoutRejecting()
    {
        var (checker, handler) = Create();
        handler.Responder = _ => throw new HttpRequestException("simulated outage");

        var decision = await checker.CheckAsync("Whatever!2026");

        Assert.False(decision.Rejected);
        Assert.Equal(PwnedPasswordOutcome.ServiceUnavailable, decision.Outcome);
    }

    [Fact]
    public async Task ServiceFailure_WithFailClosed_Rejects()
    {
        var (checker, handler) = Create(new HibpOptions { Enabled = true, FailClosed = true });
        handler.Responder = _ => throw new HttpRequestException("simulated outage");

        var decision = await checker.CheckAsync("Whatever!2026");

        Assert.True(decision.Rejected);
        Assert.Equal(PwnedPasswordOutcome.ServiceUnavailable, decision.Outcome);
    }

    public void Dispose() => cache.Dispose();
}
