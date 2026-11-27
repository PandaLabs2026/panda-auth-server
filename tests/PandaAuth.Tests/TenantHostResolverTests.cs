using Microsoft.AspNetCore.Http;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class TenantHostResolverTests
{
    [Fact]
    public void Resolves_only_an_enabled_ready_canonical_host()
    {
        var resolver = new TenantHostResolver(new TenantRoutingOptions
        {
            Bindings = [new TenantRouteBindingOptions
            {
                TenantId = "t0042",
                Product = TenantProduct.PandaAuth,
                Zone = "s001",
                RouteRevision = 3,
                State = TenantRouteState.Ready,
            }],
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0042-auth.s001.pandacloud.cc");

        var tenant = resolver.Resolve(context.Request);

        Assert.Equal("t0042", tenant.TenantId.Value);
        Assert.Equal("s001", tenant.Zone);
        Assert.Equal(3, tenant.RouteRevision);
        Assert.Equal(TenantRouteState.Ready, tenant.State);
    }

    [Theory]
    [InlineData("t0042-auth.s001.pandalabs.cn")] // Parse compatibility does not create an issuer/route alias.
    [InlineData("auth.pandalabs.cn")]
    [InlineData("t0042-auth.s002.pandalabs.cn")] // 异分区主机不得命中 s001 绑定
    [InlineData("t0043-auth.s001.pandalabs.cn")]
    [InlineData("t0042-asst.s001.pandalabs.cn")]
    [InlineData("t0042.auth.pandalabs.cn")] // 旧无分区形态已随 ADR-061 退役，fail-closed
    public void Rejects_parent_foreign_zone_or_wrong_product_hosts(string host)
    {
        var resolver = new TenantHostResolver(new TenantRoutingOptions
        {
            Bindings = [new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAuth, Zone = "s001" }],
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString(host);

        Assert.Throws<TenantContextException>(() => resolver.Resolve(context.Request));
    }

    [Fact]
    public void Rejects_non_ready_route_binding()
    {
        var resolver = new TenantHostResolver(new TenantRoutingOptions
        {
            Bindings = [new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAuth, Zone = "s001", State = TenantRouteState.Draining }],
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0042-auth.s001.pandacloud.cc");

        var error = Assert.Throws<TenantContextException>(() => resolver.Resolve(context.Request));
        Assert.Equal(TenantContextErrors.RouteNotReady, error.Code);
    }

    [Fact]
    public void AssistantProductBinding_DoesNotProduceIdpTenantContext()
    {
        // PandaAssistant 绑定只用于种子回调展开：IdP 收到 asst 主机请求时不得产生租户上下文。
        var resolver = new TenantHostResolver(new TenantRoutingOptions
        {
            Bindings =
            [
                new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAuth, Zone = "s001" },
                new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAssistant, Zone = "s001" },
            ],
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0042-asst.s001.pandalabs.cn");

        var error = Assert.Throws<TenantContextException>(() => resolver.Resolve(context.Request));
        Assert.Equal(TenantContextErrors.UnknownHost, error.Code);
    }
}

public sealed class TenantRedirectPolicyTests
{
    [Fact]
    public void Allows_same_tenant_zone_product_redirect_and_rejects_other_tenant_or_zone()
    {
        var tenant = new TenantContext(TenantId.Parse("t0042"), TenantProduct.PandaAuth, "s001",
            "t0042-auth.s001.pandacloud.cc", 1, TenantRouteState.Ready);
        var policy = new TenantRedirectPolicy();

        Assert.True(policy.IsAllowed(tenant, new Uri("https://t0042.s001.pandacloud.cc/callback/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042.s001.pandalabs.cn/callback/pandaauth"))); // F2 收口:旧后缀拒绝
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0043.s001.pandalabs.cn/callback/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042.s002.pandalabs.cn/callback/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042.s001.pandalabs.cn.evil.test/callback/pandaauth")));

        // 0.55.1：自定义 scheme 回跳（panda://callback，asst-mobile RFC 8252 形态）放行
        Assert.True(policy.IsAllowed(tenant, new Uri("panda://callback")));
        // 非 panda scheme 或 host 不匹配仍拒绝
        Assert.False(policy.IsAllowed(tenant, new Uri("evil://callback")));
        Assert.False(policy.IsAllowed(tenant, new Uri("panda://evil")));
        Assert.True(policy.IsAllowed(tenant, new Uri("https://t0042-asst.s001.pandacloud.cc/app/account/login")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-asst.s001.pandalabs.cn/app/account/login"))); // F2 收口
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0043-asst.s001.pandalabs.cn/app/account/login")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-asst.s002.pandalabs.cn/app/account/login")));
        Assert.False(policy.IsAllowed(tenant, new Uri("//t0043-asst.s001.pandalabs.cn/app")));
    }

    [Fact]
    public void Allows_the_dual_pandy_label_host_of_the_assistant_product_only()
    {
        // meta ADR-092 并存窗口：熊猫助理的 -pandy 主机与其余产品主机一样放行；其他产品没有并存标签。
        var tenant = new TenantContext(TenantId.Parse("t0042"), TenantProduct.PandaAuth, "s001",
            "t0042-auth.s001.pandacloud.cc", 1, TenantRouteState.Ready);
        var policy = new TenantRedirectPolicy();

        Assert.True(policy.IsAllowed(tenant, new Uri("https://t0042-pandy.s001.pandacloud.cc/app/callback/login/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0043-pandy.s001.pandacloud.cc/app/callback/login/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-pandy.s002.pandacloud.cc/app/callback/login/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-pandy.s001.pandalabs.cn/app/callback/login/pandaauth"))); // F2 收口
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-pandyy.s001.pandacloud.cc/app/callback/login/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-pandy.s001.pandacloud.cc.evil.test/app/callback/login/pandaauth")));
        // auth 与 oasis 产品没有并存标签。
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-pandy-oasis.s001.pandacloud.cc/login")));
    }

    [Fact]
    public void Apex_context_allows_the_dual_label_host_in_apex_form_only()
    {
        var tenant = new TenantContext(TenantId.Parse("t0042"), TenantProduct.PandaAuth, "",
            "t0042-auth.pandacloud.cc", 1, TenantRouteState.Ready);
        var policy = new TenantRedirectPolicy();

        Assert.True(policy.IsAllowed(tenant, new Uri("https://t0042-pandy.pandacloud.cc/app/callback/login/pandaauth")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0042-pandy.s001.pandacloud.cc/app/callback/login/pandaauth")));
    }
}
