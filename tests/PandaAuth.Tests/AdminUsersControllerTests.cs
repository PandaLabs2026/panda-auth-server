using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public class AdminUsersControllerTests
{
    private static (AdminUsersController Controller, ServiceProvider Provider, StubTokenRevoker Revoker) Create()
    {
        var (provider, revoker) = AdminTestHost.Create();
        var controller = new AdminUsersController(
            provider.GetRequiredService<UserManager<PandaAuthUser>>(),
            provider.GetRequiredService<ITokenRevoker>(),
            provider.GetRequiredService<AdminAuditWriter>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<AdminUsersController>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };
        return (controller, provider, revoker);
    }

    private static async Task<PandaAuthUser> SeedUserAsync(ServiceProvider provider, string userName, string? email = null, UserStatus status = UserStatus.Active)
    {
        var manager = provider.GetRequiredService<UserManager<PandaAuthUser>>();
        var user = new PandaAuthUser { UserName = userName, Email = email, Status = status };
        await manager.CreateAsync(user, "Passw0rd!1234");
        return user;
    }

    private static AdminPageResult<AdminUserSummary> PageOf(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return Assert.IsType<AdminPageResult<AdminUserSummary>>(ok.Value);
    }

    [Fact]
    public async Task List_FiltersByQueryStatusAndPages()
    {
        var (controller, provider, _) = Create();
        await SeedUserAsync(provider, "alice", "alice@example.com");
        await SeedUserAsync(provider, "bob", "bob@example.com");
        await SeedUserAsync(provider, "carol", "carol@example.com", UserStatus.Frozen);

        var byUser = PageOf(await controller.List("ALI", null, null, null, CancellationToken.None));
        Assert.Equal(1, byUser.Total);
        Assert.Equal("alice", byUser.Items.Single().UserName);

        var byStatus = PageOf(await controller.List(null, UserStatus.Frozen, null, null, CancellationToken.None));
        Assert.Equal("carol", byStatus.Items.Single().UserName);

        var paged = PageOf(await controller.List(null, null, 1, 2, CancellationToken.None));
        Assert.Equal(3, paged.Total);
        Assert.Equal(2, paged.Items.Count);
        Assert.Equal(2, paged.PageSize);

        // 上限保护：pageSize 超过 MaxPageSize 被钳制而不是放大查询。
        var capped = PageOf(await controller.List(null, null, 1, 9999, CancellationToken.None));
        Assert.Equal(AdminUsersController.MaxPageSize, capped.PageSize);
    }

    [Fact]
    public async Task Detail_ReturnsRolesAndLockoutFields()
    {
        var (controller, provider, _) = Create();
        var user = await SeedUserAsync(provider, "dave");
        var roleManager = provider.GetRequiredService<RoleManager<PandaAuthRole>>();
        await roleManager.CreateAsync(new PandaAuthRole { Name = PandaAuthUser.AdminRole });
        await provider.GetRequiredService<UserManager<PandaAuthUser>>().AddToRoleAsync(user, PandaAuthUser.AdminRole);

        var ok = Assert.IsType<OkObjectResult>(await controller.Detail(user.Id));
        var detail = Assert.IsType<AdminUserDetail>(ok.Value);
        Assert.Equal("dave", detail.UserName);
        Assert.Contains(PandaAuthRoles.Admin, detail.Roles);
    }

    [Fact]
    public async Task Freeze_SetsStatus_RevokesTokens_WritesAudit()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "eve");

        var ok = Assert.IsType<OkObjectResult>(
            await controller.SetStatus(user.Id, new AdminUserStatusRequest(UserStatus.Frozen), CancellationToken.None));
        Assert.Equal(UserStatus.Frozen, Assert.IsType<AdminUserSummary>(ok.Value).Status);

        // 用户侧
        Assert.Equal(UserStatus.Frozen,
            (await provider.GetRequiredService<UserManager<PandaAuthUser>>().FindByIdAsync(user.Id))!.Status);
        // 令牌吊销恰好一次、目标是该用户
        Assert.Equal([user.Id], revoker.RevokedUsers);
        // 审计：动作、操作者、目标、IP（来自测试HttpContext的连接层）
        var entry = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
        Assert.Equal(AdminAuditAction.UserFreeze, entry.Action);
        Assert.Equal("actor-1", entry.ActorUserId);
        Assert.Equal("admin", entry.ActorUserName);
        Assert.Equal(user.Id, entry.TargetId);
        Assert.Equal("203.0.113.10", entry.IpAddress);
        Assert.Contains("Active", entry.Detail);
        Assert.Contains("Frozen", entry.Detail);
    }

    [Fact]
    public async Task Unfreeze_IsAuditedSeparately()
    {
        var (controller, provider, _) = Create();
        var user = await SeedUserAsync(provider, "frank", status: UserStatus.Frozen);

        Assert.IsType<OkObjectResult>(
            await controller.SetStatus(user.Id, new AdminUserStatusRequest(UserStatus.Active), CancellationToken.None));
        var entry = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
        Assert.Equal(AdminAuditAction.UserUnfreeze, entry.Action);
    }

    [Fact]
    public async Task SetStatus_Idempotent_NoRevocationNoAudit()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "grace"); // Active

        var ok = Assert.IsType<OkObjectResult>(
            await controller.SetStatus(user.Id, new AdminUserStatusRequest(UserStatus.Active), CancellationToken.None));
        Assert.Equal(UserStatus.Active, Assert.IsType<AdminUserSummary>(ok.Value).Status);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Theory]
    [InlineData(UserStatus.Deleted)]
    public async Task SetStatus_RejectsNonToggleableStatus(UserStatus status)
    {
        var (controller, provider, _) = Create();
        var user = await SeedUserAsync(provider, "heidi");

        var problem = Assert.IsType<ObjectResult>(
            await controller.SetStatus(user.Id, new AdminUserStatusRequest(status), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);
    }

    [Fact]
    public async Task ResetPassword_GeneratesCompliantPassword_Revokes_Audits()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "ivan");
        // 快照值而不是引用：user 是被跟踪的实体，控制器操作会就地改它。
        var stampBefore = user.SecurityStamp;

        var ok = Assert.IsType<OkObjectResult>(
            await controller.ResetPassword(user.Id, null, CancellationToken.None));
        var password = Assert.IsType<AdminResetPasswordResponse>(ok.Value).Password;

        // 生成的密码真实可用（走 UserManager 校验与哈希验证）。
        var manager = provider.GetRequiredService<UserManager<PandaAuthUser>>();
        var reloaded = await manager.FindByIdAsync(user.Id);
        Assert.True(await manager.CheckPasswordAsync(reloaded!, password));
        // 安全戳被刷新（Cookie 会话失效口径）。
        Assert.NotEqual(stampBefore, reloaded!.SecurityStamp);
        Assert.Equal([user.Id], revoker.RevokedUsers);
        Assert.Equal(AdminAuditAction.UserResetPassword,
            Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable()).Action);
    }

    [Fact]
    public async Task ResetPassword_WithCustomPassword_SucceedsAndAuditsGeneratedFalse()
    {
        var (controller, provider, _) = Create();
        var user = await SeedUserAsync(provider, "judy");

        var ok = Assert.IsType<OkObjectResult>(
            await controller.ResetPassword(user.Id, new AdminResetPasswordRequest("Custom!Passw0rdX"), CancellationToken.None));
        Assert.Equal("Custom!Passw0rdX", Assert.IsType<AdminResetPasswordResponse>(ok.Value).Password);

        var manager = provider.GetRequiredService<UserManager<PandaAuthUser>>();
        Assert.True(await manager.CheckPasswordAsync((await manager.FindByIdAsync(user.Id))!, "Custom!Passw0rdX"));
        Assert.Contains("generated\":false", Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable()).Detail);
    }

    [Fact]
    public async Task ResetPassword_WithInvalidCustomPassword_RejectsAndKeepsOldPasswordWorking()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "kate"); // 初始密码 Passw0rd!1234

        var problem = Assert.IsType<ObjectResult>(
            await controller.ResetPassword(user.Id, new AdminResetPasswordRequest("short"), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        // 关键回归：失败路径必须回滚旧哈希——账号仍能用旧密码登录，而不是被锁死。
        var manager = provider.GetRequiredService<UserManager<PandaAuthUser>>();
        Assert.True(await manager.CheckPasswordAsync((await manager.FindByIdAsync(user.Id))!, "Passw0rd!1234"));
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }
}
