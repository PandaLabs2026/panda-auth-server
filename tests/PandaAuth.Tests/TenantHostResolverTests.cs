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
                RouteRevision = 3,
                State = TenantRouteState.Ready,
            }],
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0042.auth.pandalabs.cn");

        var tenant = resolver.Resolve(context.Request);

        Assert.Equal("t0042", tenant.TenantId.Value);
        Assert.Equal(3, tenant.RouteRevision);
        Assert.Equal(TenantRouteState.Ready, tenant.State);
    }

    [Theory]
    [InlineData("auth.pandalabs.cn")]
    [InlineData("t0043.auth.pandalabs.cn")]
    [InlineData("t0042.assistant.pandalabs.cn")]
    public void Rejects_parent_foreign_or_wrong_product_hosts(string host)
    {
        var resolver = new TenantHostResolver(new TenantRoutingOptions
        {
            Bindings = [new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAuth }],
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
            Bindings = [new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAuth, State = TenantRouteState.Draining }],
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0042.auth.pandalabs.cn");

        var error = Assert.Throws<TenantContextException>(() => resolver.Resolve(context.Request));
        Assert.Equal(TenantContextErrors.RouteNotReady, error.Code);
    }
}

public sealed class TenantRedirectPolicyTests
{
    [Fact]
    public void Allows_same_tenant_product_redirect_and_rejects_other_tenant()
    {
        var tenant = new TenantContext(TenantId.Parse("t0042"), TenantProduct.PandaAuth,
            "t0042.auth.pandalabs.cn", 1, TenantRouteState.Ready);
        var policy = new TenantRedirectPolicy();

        Assert.True(policy.IsAllowed(tenant, new Uri("https://t0042.assistant.pandalabs.cn/app/account/login")));
        Assert.False(policy.IsAllowed(tenant, new Uri("https://t0043.assistant.pandalabs.cn/app/account/login")));
        Assert.False(policy.IsAllowed(tenant, new Uri("//t0043.assistant.pandalabs.cn/app")));
    }
}
