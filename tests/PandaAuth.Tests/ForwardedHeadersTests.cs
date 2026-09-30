using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// ForwardedHeaders 收敛回归测试：直接以 ForwardedHeadersMiddleware 构造 HttpContext，
/// 验证仅回环代理信任 + ForwardedLimit=1 时，伪造 X-Forwarded-For 无法污染 RemoteIpAddress
/// （IP 维度登录限流依赖还原后的客户端 IP）。
/// </summary>
public class ForwardedHeadersTests
{
    private const string ForgedIp = "1.2.3.4";
    private static readonly IPAddress TenantGateway = IPAddress.Parse("100.64.3.1");

    private static readonly IPAddress RealClientIp = IPAddress.Parse("203.0.113.9");

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public async Task LoopbackProxy_ForgedLeftmostIsIgnored_AndRealClientRestored(string proxyIp)
    {
        // 攻击者向 Caddy 发送伪造 XFF 最左值；Caddy（回环代理）追加真实客户端 IP 到最右。
        var context = CreateContext(IPAddress.Parse(proxyIp), $"{ForgedIp}, {RealClientIp}", "https");
        await InvokeForwardedHeadersAsync(context);

        var restored = context.Connection.RemoteIpAddress;
        Assert.NotNull(restored);
        // 还原结果不得为攻击者伪造值（ForwardedLimit=1 只消费 Caddy 追加的最右一跳）。
        Assert.NotEqual(IPAddress.Parse(ForgedIp), restored);
        Assert.Equal(RealClientIp, restored);
        // Caddy 终结 TLS，Scheme 须一并还原。
        Assert.Equal("https", context.Request.Scheme);
    }

    [Fact]
    public async Task LoopbackProxy_SingleClientIp_IsRestored()
    {
        // Caddy 覆写 XFF 为直连客户端 IP（单值）：一跳也须正确还原，正常流量不受影响。
        var context = CreateContext(IPAddress.Loopback, RealClientIp.ToString(), "https");
        await InvokeForwardedHeadersAsync(context);

        Assert.Equal(RealClientIp, context.Connection.RemoteIpAddress);
        Assert.Equal("https", context.Request.Scheme);
    }

    [Fact]
    public async Task NonProxyPeer_IgnoresForwardedHeaders()
    {
        // 非回环直连（绕过 Caddy 的请求）：伪造 XFF 一律不采信，RemoteIpAddress 保持真实对端。
        // 旧配置信任全量网段时本测试失败（RemoteIpAddress 会被污染为伪造值）。
        var peer = IPAddress.Parse("198.51.100.7");
        var context = CreateContext(peer, ForgedIp, "https");
        await InvokeForwardedHeadersAsync(context);

        Assert.Equal(peer, context.Connection.RemoteIpAddress);
        Assert.Equal("http", context.Request.Scheme);
    }

    [Fact]
    public async Task TenantBridge_TrustsOnlyTheConfiguredGateway()
    {
        var options = CreateForwardedHeadersOptions(new Dictionary<string, string?>
        {
            ["PANDA_AUTH_TENANT_NETWORK_MODE"] = "bridge",
            ["PANDA_AUTH_TRUSTED_PROXY"] = TenantGateway.ToString(),
        });
        var context = CreateContext(TenantGateway, RealClientIp.ToString(), "https");

        await InvokeForwardedHeadersAsync(context, options);

        Assert.Equal(RealClientIp, context.Connection.RemoteIpAddress);
        Assert.Equal("https", context.Request.Scheme);
        Assert.Contains(TenantGateway, options.KnownProxies);
        Assert.DoesNotContain(IPAddress.Loopback, options.KnownProxies);
    }

    [Theory]
    [InlineData("100.64.3.2")]
    [InlineData("127.0.0.1")]
    public async Task TenantBridge_RejectsForwardedHeadersFromAnyOtherPeer(string peerAddress)
    {
        var options = CreateForwardedHeadersOptions(new Dictionary<string, string?>
        {
            ["PANDA_AUTH_TENANT_NETWORK_MODE"] = "bridge",
            ["PANDA_AUTH_TRUSTED_PROXY"] = TenantGateway.ToString(),
        });
        var peer = IPAddress.Parse(peerAddress);
        var context = CreateContext(peer, ForgedIp, "https");

        await InvokeForwardedHeadersAsync(context, options);

        Assert.Equal(peer, context.Connection.RemoteIpAddress);
        Assert.Equal("http", context.Request.Scheme);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("100.64.3.0/24")]
    [InlineData("not-an-ip")]
    public void TenantBridge_RequiresOneValidProxyIp(string? trustedProxy)
    {
        var settings = new Dictionary<string, string?>
        {
            ["PANDA_AUTH_TENANT_NETWORK_MODE"] = "bridge",
        };
        if (trustedProxy is not null) settings["PANDA_AUTH_TRUSTED_PROXY"] = trustedProxy;

        Assert.Throws<InvalidOperationException>(() => CreateForwardedHeadersOptions(settings));
    }

    private static DefaultHttpContext CreateContext(IPAddress remoteIp, string forwardedFor, string? forwardedProto)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = remoteIp;
        context.Request.Scheme = "http";
        context.Request.Headers["X-Forwarded-For"] = forwardedFor;
        if (forwardedProto is not null)
        {
            context.Request.Headers["X-Forwarded-Proto"] = forwardedProto;
        }

        return context;
    }

    private static Task InvokeForwardedHeadersAsync(HttpContext context, ForwardedHeadersOptions? options = null)
    {
        // 与 Program.cs 的 app.UseForwardedHeaders(...) 配置保持一致（仅回环代理 + ForwardedLimit=1）。
        options ??= CreateForwardedHeadersOptions(new Dictionary<string, string?>());
        var middleware = new ForwardedHeadersMiddleware(
            static _ => Task.CompletedTask,
            NullLoggerFactory.Instance,
            Options.Create(options));
        return middleware.Invoke(context);
    }

    private static ForwardedHeadersOptions CreateForwardedHeadersOptions(IDictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            ForwardLimit = 1,
        };
        TenantForwardedHeaders.Configure(options, configuration);
        return options;
    }
}
