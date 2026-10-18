using Microsoft.AspNetCore.Http;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class TenantHostMiddlewareTests
{
    private static TenantRoutingOptions EnabledOptions() => new()
    {
        Enabled = true,
        Bindings =
        [
            new TenantRouteBindingOptions
            {
                TenantId = "t0042",
                Product = TenantProduct.PandaAuth,
                Zone = "s001",
                State = TenantRouteState.Ready,
            },
        ],
    };

    [Fact]
    public async Task CanonicalHost_SetsTenantContext()
    {
        var options = EnabledOptions();
        var accessor = new TenantContextAccessor();
        var called = false;
        var middleware = new TenantHostMiddleware(_ =>
        {
            called = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0042-auth.s001.pandalabs.cn");

        await middleware.InvokeAsync(context, new TenantHostResolver(options), accessor, options);

        Assert.True(called);
        Assert.NotNull(accessor.Current);
        Assert.Equal("t0042", accessor.Current!.TenantId.Value);
    }

    [Fact]
    public async Task UnknownCanonicalHost_FailsClosedWith421()
    {
        var options = EnabledOptions();
        var accessor = new TenantContextAccessor();
        var called = false;
        var middleware = new TenantHostMiddleware(_ =>
        {
            called = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0043-auth.s001.pandalabs.cn");

        await middleware.InvokeAsync(context, new TenantHostResolver(options), accessor, options);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status421MisdirectedRequest, context.Response.StatusCode);
        Assert.Null(accessor.Current);
    }

    [Fact]
    public async Task Disabled_PreservesLegacyPassthrough()
    {
        var options = EnabledOptions();
        options.Enabled = false;
        var accessor = new TenantContextAccessor();
        var called = false;
        var middleware = new TenantHostMiddleware(_ =>
        {
            called = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("t0042-auth.s001.pandalabs.cn");

        await middleware.InvokeAsync(context, new TenantHostResolver(options), accessor, options);

        Assert.True(called);
        Assert.Null(accessor.Current);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("auth.pandalabs.cn")]
    [InlineData("t0042.auth.pandalabs.cn")]
    public async Task NonCanonicalHost_IsNotTreatedAsTenantHost(string host)
    {
        var options = EnabledOptions();
        var accessor = new TenantContextAccessor();
        var called = false;
        var middleware = new TenantHostMiddleware(_ =>
        {
            called = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString(host);

        await middleware.InvokeAsync(context, new TenantHostResolver(options), accessor, options);

        Assert.True(called);
        Assert.Null(accessor.Current);
    }
}
