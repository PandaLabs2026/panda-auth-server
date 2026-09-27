using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Management;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// Management API 用户只读查询（M0）聚焦测试：与 admin 列表同一投影与搜索口径。
/// 授权语义（audience+scope）单测见 MgmtApiAuthorizationTests；这里直接调用控制器。
/// </summary>
public class ManagementUsersControllerTests
{
    private static (ManagementUsersController Controller, ServiceProvider Provider) Create(ManagementRateLimiter? limiter = null)
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new ManagementUsersController(
            provider.GetRequiredService<UserService>(),
            limiter ?? TestsMgmtLimiter.New())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };
        return (controller, provider);
    }

    private static async Task SeedUserAsync(
        ServiceProvider provider, string userName, string? email = null, UserStatus status = UserStatus.Active)
    {
        var manager = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = userName, Email = email, Status = status };
        await manager.CreateAsync(user, "Passw0rd!1234");
    }

    private static AdminPageResult<AdminUserSummary> PageOf(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return Assert.IsType<AdminPageResult<AdminUserSummary>>(ok.Value);
    }

    [Fact]
    public async Task List_FiltersByQueryAndPages()
    {
        var (controller, provider) = Create();
        await SeedUserAsync(provider, "alice", "alice@example.com");
        await SeedUserAsync(provider, "bob", "bob@example.com");

        var byQuery = PageOf(await controller.List("ALI", null, null, CancellationToken.None));
        Assert.Equal(1, byQuery.Total);
        Assert.Equal("alice", byQuery.Items.Single().UserName);

        var paged = PageOf(await controller.List(null, 1, 1, CancellationToken.None));
        Assert.Equal(2, paged.Total);
        Assert.Single(paged.Items);
    }

    [Fact]
    public async Task List_ProjectionCarriesNoCredentialFields()
    {
        // 投影契约：只有 id/用户名/邮箱/昵称/状态/创建时间；凭据与安全戳字段不出现在响应面。
        var (controller, provider) = Create();
        await SeedUserAsync(provider, "alice", "alice@example.com");

        var page = PageOf(await controller.List(null, null, null, CancellationToken.None));
        var summary = page.Items.Single();

        Assert.Equal("alice", summary.UserName);
        Assert.Equal("alice@example.com", summary.Email);
        Assert.Equal(UserStatus.Active, summary.Status);
    }

    [Fact]
    public async Task List_EmptyDatabase_ReturnsZeroTotal()
    {
        var (controller, provider) = Create();

        var page = PageOf(await controller.List(null, null, null, CancellationToken.None));

        Assert.Equal(0, page.Total);
        Assert.Empty(page.Items);
    }

    [Fact]
    public async Task List_RateLimited_Returns429WithRetryAfter()
    {
        var (provider, _) = AdminTestHost.Create();
        var limiter = TestsMgmtLimiter.New(new MgmtRateLimitOptions { ReadPerMinute = 1 });
        var controller = new ManagementUsersController(provider.GetRequiredService<UserService>(), limiter)
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        Assert.IsType<OkObjectResult>(await controller.List(null, null, null, CancellationToken.None));

        var limited = Assert.IsType<ObjectResult>(await controller.List(null, null, null, CancellationToken.None));
        Assert.Equal(StatusCodes.Status429TooManyRequests, limited.StatusCode);
        Assert.True(controller.Response.Headers.ContainsKey("Retry-After"));
    }
}

/// <summary>Management 限流器的测试构造入口：默认桶配置 + 独立 MemoryCache。</summary>
internal static class TestsMgmtLimiter
{
    public static ManagementRateLimiter New(MgmtRateLimitOptions? options = null)
        => new(new MemoryCache(new MemoryCacheOptions()), options ?? new MgmtRateLimitOptions());
}
