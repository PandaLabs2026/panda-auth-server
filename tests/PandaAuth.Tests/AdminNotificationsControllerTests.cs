using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 通知中心：审计派生列表（Id 倒序）+ 每管理员游标（默认 0 / 单调不回退 / 多管理员隔离）。
/// </summary>
public class AdminNotificationsControllerTests
{
    private static (AdminNotificationsController Controller, ServiceProvider Provider) Create()
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new AdminNotificationsController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };
        return (controller, provider);
    }

    private static async Task<ServiceProvider> SeedAsync(ServiceProvider provider, int auditCount = 3)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        for (var i = 1; i <= auditCount; i++)
        {
            db.AdminAuditLogs.Add(new AdminAuditLog
            {
                ActorUserId = i % 2 == 0 ? "actor-2" : "actor-1",
                ActorUserName = i % 2 == 0 ? "ops" : "admin",
                Action = AdminAuditAction.UserFreeze,
                TargetType = "user",
                TargetId = $"u-{i}",
                CreatedAt = DateTimeOffset.Parse("2026-10-01T00:00:00Z").AddHours(i),
            });
        }
        await db.SaveChangesAsync();
        return provider;
    }

    private static AdminPageResult<T> PageOf<T>(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return Assert.IsType<AdminPageResult<T>>(ok.Value);
    }

    [Theory]
    [InlineData(int.MaxValue)]
    [InlineData(1_073_741_825)]
    public async Task List_OverflowingOffset_ReturnsEmptyPage(int requestedPage)
    {
        var (controller, provider) = Create();
        await using var ownedProvider = provider;
        await SeedAsync(provider);

        var page = PageOf<AdminNotificationEntry>(await controller.List(requestedPage, 20, CancellationToken.None));

        Assert.Equal(3, page.Total);
        Assert.Equal(requestedPage, page.Page);
        Assert.Equal(20, page.PageSize);
        Assert.Empty(page.Items);
    }

    [Fact]
    public async Task List_ReturnsAuditEntriesInIdDescendingOrder()
    {
        var (controller, provider) = Create();
        await SeedAsync(provider, 3);
        await using (provider)
        {
            var page = PageOf<AdminNotificationEntry>(await controller.List(null, null, CancellationToken.None));
            Assert.Equal(3, page.Total);
            // Id 倒序（通知语义：最新在前），字段与审计条目一一对齐。
            Assert.Equal([3, 2, 1], page.Items.Select(entry => entry.Id));
            var first = page.Items[0];
            Assert.Equal("actor-1", first.ActorUserId);
            Assert.Equal(AdminAuditAction.UserFreeze, first.Action);
            Assert.Equal("u-3", first.TargetId);
        }
    }

    [Fact]
    public async Task GetCursor_ReturnsZero_WhenAdminHasNoRow()
    {
        var (controller, provider) = Create();
        await using (provider)
        {
            var ok = Assert.IsType<OkObjectResult>(await controller.GetCursor(CancellationToken.None));
            var cursor = Assert.IsType<AdminSeenCursor>(ok.Value);
            Assert.Equal(0, cursor.LastAuditId);
        }
    }

    [Fact]
    public async Task SetCursor_InsertsThenAdvances_AndIgnoresRegression()
    {
        var (controller, provider) = Create();
        await using (provider)
        {
            var ok = Assert.IsType<OkObjectResult>(await controller.SetCursor(new AdminSeenCursorRequest(7), CancellationToken.None));
            Assert.Equal(7, Assert.IsType<AdminSeenCursor>(ok.Value).LastAuditId);

            // 前进生效。
            ok = Assert.IsType<OkObjectResult>(await controller.SetCursor(new AdminSeenCursorRequest(12), CancellationToken.None));
            Assert.Equal(12, Assert.IsType<AdminSeenCursor>(ok.Value).LastAuditId);

            // 回退幂等忽略：不报错、不回退（「全部已读」后晚到的旧上报不该把水位拉回去）。
            ok = Assert.IsType<OkObjectResult>(await controller.SetCursor(new AdminSeenCursorRequest(3), CancellationToken.None));
            Assert.Equal(12, Assert.IsType<AdminSeenCursor>(ok.Value).LastAuditId);
        }
    }

    [Fact]
    public async Task SetCursor_RejectsNegativeId()
    {
        var (controller, provider) = Create();
        await using (provider)
        {
            var problem = Assert.IsType<ObjectResult>(await controller.SetCursor(new AdminSeenCursorRequest(-1), CancellationToken.None));
            Assert.Equal(400, problem.StatusCode);
        }
    }

    [Fact]
    public async Task Cursor_IsIsolatedPerAdminUser()
    {
        var (controller, provider) = Create();
        await using (provider)
        {
            await controller.SetCursor(new AdminSeenCursorRequest(9), CancellationToken.None);

            // 换一个管理员主体（sub=actor-2）：各自水位互不可见。
            var otherPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "actor-2"),
                new Claim("name", "ops"),
                new Claim("role", PandaAuthRoles.Admin),
            ], "TestBearer", "name", "role"));
            var other = new AdminNotificationsController(provider.GetRequiredService<PandaAuthDbContext>())
            {
                ControllerContext = new() { HttpContext = new DefaultHttpContext { User = otherPrincipal, RequestServices = provider } },
            };

            var ok = Assert.IsType<OkObjectResult>(await other.GetCursor(CancellationToken.None));
            Assert.Equal(0, Assert.IsType<AdminSeenCursor>(ok.Value).LastAuditId);

            // actor-2 写入自己的水位，不影响 actor-1。
            await other.SetCursor(new AdminSeenCursorRequest(20), CancellationToken.None);
            ok = Assert.IsType<OkObjectResult>(await controller.GetCursor(CancellationToken.None));
            Assert.Equal(9, Assert.IsType<AdminSeenCursor>(ok.Value).LastAuditId);
        }
    }
}
