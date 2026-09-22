using System.Security.Claims;
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
            provider.GetRequiredService<UserService>(),
            provider.GetRequiredService<RoleService>(),
            provider.GetRequiredService<SessionSecurityService>(),
            provider.GetRequiredService<AdminAuditWriter>(),
            provider.GetRequiredService<SecurityEventWriter>(),
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<AdminUsersController>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };
        return (controller, provider, revoker);
    }

    private static async Task<PandaUser> SeedUserAsync(ServiceProvider provider, string userName, string? email = null, UserStatus status = UserStatus.Active)
    {
        var manager = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = userName, Email = email, Status = status };
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
        var roleManager = provider.GetRequiredService<RoleService>();
        await roleManager.CreateAsync(new PandaRole { Name = PandaUser.AdminRole });
        await provider.GetRequiredService<UserService>().AddToRoleAsync(user, PandaUser.AdminRole);

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
            (await provider.GetRequiredService<UserService>().FindByIdAsync(user.Id))!.Status);
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
        var securityEvent = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents);
        Assert.Equal("user.status_changed", securityEvent.EventType);
        Assert.Equal(user.Id, securityEvent.UserId);
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
    public async Task SetStatus_RejectsTransitionsFromDeleted()
    {
        var (controller, provider, revoker) = Create();
        // 终态守卫：解冻/冻结请求不得「复活」已注销账号（绕过注销的逐字确认门禁）。
        var user = await SeedUserAsync(provider, "deleted-target", status: UserStatus.Deleted);

        var problem = Assert.IsType<ObjectResult>(
            await controller.SetStatus(user.Id, new AdminUserStatusRequest(UserStatus.Active), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        Assert.Equal(UserStatus.Deleted,
            (await provider.GetRequiredService<UserService>().FindByIdAsync(user.Id))!.Status);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
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
        var manager = provider.GetRequiredService<UserService>();
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

        var manager = provider.GetRequiredService<UserService>();
        Assert.True(await manager.CheckPasswordAsync((await manager.FindByIdAsync(user.Id))!, "Custom!Passw0rdX"));
        Assert.Contains("generated\":false", Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable()).Detail);
    }

    [Fact]
    public async Task ResetPassword_WithoutMfa_IsForbiddenBeforeMutation()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "reset-without-mfa");
        controller.ControllerContext.HttpContext.User = AdminTestHost.AdminPrincipalWithoutMfa();

        var result = await controller.ResetPassword(user.Id, null, CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
        Assert.Empty(revoker.RevokedUsers);
    }

    [Fact]
    public async Task Create_WithoutMfa_IsForbiddenBeforeMutation()
    {
        var (controller, provider, _) = Create();
        controller.ControllerContext.HttpContext.User = AdminTestHost.AdminPrincipalWithoutMfa();

        var result = await controller.Create(
            new AdminCreateUserRequest("create-without-mfa", null, null, null, null, GrantAdminRole: false),
            CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
        Assert.Null(await provider.GetRequiredService<UserService>().FindByNameAsync("create-without-mfa"));
    }

    [Fact]
    public async Task SetStatus_ByTheAccountOwnerIsRejected()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "self-freeze");

        controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(Claims.Subject, user.Id),
            new Claim(Claims.Name, "self-freeze"),
            new Claim(Claims.Role, PandaAuthRoles.Admin),
            new Claim(PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.Method, PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.WebAuthn),
            new Claim(PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        ], "TestBearer", Claims.Name, Claims.Role));

        var problem = Assert.IsType<ObjectResult>(
            await controller.SetStatus(user.Id, new AdminUserStatusRequest(UserStatus.Frozen), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        // 未发生状态变更、吊销与审计。
        Assert.Equal(UserStatus.Active,
            (await provider.GetRequiredService<UserService>().FindByIdAsync(user.Id))!.Status);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task ResetPassword_ByTheAccountOwnerIsRejected()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "self-reset");

        // 把操作者主体换成目标账号本人（sub 对齐），断言自重置被拒且无任何副作用。
        controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(Claims.Subject, user.Id),
            new Claim(Claims.Name, "self-reset"),
            new Claim(Claims.Role, PandaAuthRoles.Admin),
            new Claim(PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.Method, PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.WebAuthn),
            new Claim(PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        ], "TestBearer", Claims.Name, Claims.Role));

        var problem = Assert.IsType<ObjectResult>(
            await controller.ResetPassword(user.Id, null, CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        // 未发生密码变更、吊销与审计。
        var manager = provider.GetRequiredService<UserService>();
        Assert.True(await manager.CheckPasswordAsync((await manager.FindByIdAsync(user.Id))!, "Passw0rd!1234"));
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task ResetPassword_WithInvalidCustomPassword_RejectsAndKeepsOldPasswordWorking()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "kate"); // 初始密码 Passw0rd!1234
        var stampBefore = user.SecurityStamp;

        var problem = Assert.IsType<ObjectResult>(
            await controller.ResetPassword(user.Id, new AdminResetPasswordRequest("short"), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        // 关键回归：失败路径必须回滚旧哈希——账号仍能用旧密码登录，而不是被锁死。
        var manager = provider.GetRequiredService<UserService>();
        var reloaded = await manager.FindByIdAsync(user.Id);
        Assert.True(await manager.CheckPasswordAsync(reloaded!, "Passw0rd!1234"));
        // 失败路径不得留下任何副作用：AddPasswordAsync 内部轮换过的安全戳必须一并还原，
        // 否则一次「没发生的」重置也会把目标既有 Cookie 会话全部踹下线。
        Assert.Equal(stampBefore, reloaded!.SecurityStamp);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    // ---- 建号（Create） ----

    private static AdminUserDetail DetailOf(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return Assert.IsType<AdminUserDetail>(ok.Value);
    }

    private static AdminAuditLog SingleAudit(ServiceProvider provider)
        => Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());

    private static void ActAs(AdminUsersController controller, string userId, string userName)
        => controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(Claims.Subject, userId),
            new Claim(Claims.Name, userName),
            new Claim(Claims.Role, PandaAuthRoles.Admin),
            new Claim(PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.Method, PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.WebAuthn),
            new Claim(PandaAuth.Server.Infrastructure.Security.Mfa.MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        ], "TestBearer", Claims.Name, Claims.Role));

    private static async Task EnsureAdminRoleAsync(ServiceProvider provider)
    {
        var roleManager = provider.GetRequiredService<RoleService>();
        if (!await roleManager.RoleExistsAsync(PandaUser.AdminRole))
        {
            await roleManager.CreateAsync(new PandaRole { Name = PandaUser.AdminRole });
        }
    }

    [Fact]
    public async Task Create_GeneratesPassword_SetsAdminChannel_Audits()
    {
        var (controller, provider, _) = Create();
        var manager = provider.GetRequiredService<UserService>();

        var ok = Assert.IsType<OkObjectResult>(
            await controller.Create(new AdminCreateUserRequest("new-user", "new@example.com", "纽", null, null, GrantAdminRole: false), CancellationToken.None));
        var response = Assert.IsType<AdminCreateUserResponse>(ok.Value);

        // 生成的明文密码仅本次返回且真实可用。
        Assert.False(string.IsNullOrEmpty(response.Password));
        var reloaded = await manager.FindByIdAsync(response.Id);
        Assert.True(await manager.CheckPasswordAsync(reloaded!, response.Password!));
        Assert.Equal(RegisterChannel.Admin, reloaded!.RegisterChannel);
        Assert.False(reloaded.EmailConfirmed);
        Assert.Equal(AdminAuditAction.UserCreate, SingleAudit(provider).Action);
        Assert.Contains("generatedPassword\":true", SingleAudit(provider).Detail);
    }

    [Fact]
    public async Task Create_WithCustomPassword_DoesNotReturnPlaintext()
    {
        var (controller, provider, _) = Create();
        var manager = provider.GetRequiredService<UserService>();

        var ok = Assert.IsType<OkObjectResult>(
            await controller.Create(new AdminCreateUserRequest("custom-pw", null, null, null, "Custom!Passw0rdX", GrantAdminRole: false), CancellationToken.None));
        var response = Assert.IsType<AdminCreateUserResponse>(ok.Value);

        Assert.Null(response.Password);
        Assert.True(await manager.CheckPasswordAsync((await manager.FindByIdAsync(response.Id))!, "Custom!Passw0rdX"));
        Assert.Contains("generatedPassword\":false", SingleAudit(provider).Detail);
    }

    [Fact]
    public async Task Create_RejectsDuplicateUserName()
    {
        var (controller, provider, _) = Create();
        await SeedUserAsync(provider, "dup-user");

        var problem = Assert.IsType<ObjectResult>(
            await controller.Create(new AdminCreateUserRequest("dup-user", null, null, null, null, GrantAdminRole: false), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);
    }

    [Fact]
    public async Task Create_RejectsWeakPassword()
    {
        var (controller, provider, _) = Create();

        var problem = Assert.IsType<ObjectResult>(
            await controller.Create(new AdminCreateUserRequest("weak-pw", null, null, null, "short", GrantAdminRole: false), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);
        // 账号未残留：策略不过的建号不落库。
        Assert.Null(await provider.GetRequiredService<UserService>().FindByNameAsync("weak-pw"));
    }

    [Fact]
    public async Task Create_GrantAdminRole_AssignsAdminRole()
    {
        var (controller, provider, _) = Create();
        await EnsureAdminRoleAsync(provider);

        var ok = Assert.IsType<OkObjectResult>(
            await controller.Create(new AdminCreateUserRequest("born-admin", null, null, null, null, GrantAdminRole: true), CancellationToken.None));
        var response = Assert.IsType<AdminCreateUserResponse>(ok.Value);

        Assert.Contains(PandaAuthRoles.Admin,
            await provider.GetRequiredService<UserService>().GetRolesAsync(
                (await provider.GetRequiredService<UserService>().FindByIdAsync(response.Id))!));
    }

    [Fact]
    public async Task Create_GrantAdminRole_WithoutSeededRole_AccountStillCreatedAndAudited()
    {
        var (controller, provider, _) = Create();
        // 刻意不播种 admin 角色：部分成功必须留痕（账号建成即审计），并如实报 500 指引补救。
        var manager = provider.GetRequiredService<UserService>();

        var problem = Assert.IsType<ObjectResult>(
            await controller.Create(new AdminCreateUserRequest("orphan-admin", null, null, null, null, GrantAdminRole: true), CancellationToken.None));
        Assert.Equal(StatusCodes.Status500InternalServerError, problem.StatusCode);

        var created = await manager.FindByNameAsync("orphan-admin");
        Assert.NotNull(created);
        var entry = SingleAudit(provider);
        Assert.Equal(AdminAuditAction.UserCreate, entry.Action);
        Assert.Contains("roleGrantError", entry.Detail);
    }

    // ---- 角色管理（UpdateRoles） ----

    [Fact]
    public async Task UpdateRoles_GrantsAdmin_Revokes_Audits()
    {
        var (controller, provider, revoker) = Create();
        await EnsureAdminRoleAsync(provider);
        var user = await SeedUserAsync(provider, "role-grant");
        var stampBefore = user.SecurityStamp;

        var detail = DetailOf(await controller.UpdateRoles(user.Id, new AdminUserRolesRequest([PandaAuthRoles.Admin]), CancellationToken.None));

        Assert.Equal([PandaAuthRoles.Admin], detail.Roles);
        Assert.NotEqual(stampBefore, user.SecurityStamp);
        Assert.Equal([user.Id], revoker.RevokedUsers);
        var entry = SingleAudit(provider);
        Assert.Equal(AdminAuditAction.UserUpdateRoles, entry.Action);
        Assert.Contains("admin", entry.Detail);
    }

    [Fact]
    public async Task UpdateRoles_RemovesAdmin()
    {
        var (controller, provider, revoker) = Create();
        await EnsureAdminRoleAsync(provider);
        var user = await SeedUserAsync(provider, "role-remove");
        await provider.GetRequiredService<UserService>().AddToRoleAsync(user, PandaUser.AdminRole);

        var detail = DetailOf(await controller.UpdateRoles(user.Id, new AdminUserRolesRequest([]), CancellationToken.None));

        Assert.Empty(detail.Roles);
        Assert.Equal([user.Id], revoker.RevokedUsers);
        Assert.Equal(AdminAuditAction.UserUpdateRoles, SingleAudit(provider).Action);
    }

    [Fact]
    public async Task UpdateRoles_RejectsSelfDemotion()
    {
        var (controller, provider, revoker) = Create();
        await EnsureAdminRoleAsync(provider);
        var user = await SeedUserAsync(provider, "self-demote");
        await provider.GetRequiredService<UserService>().AddToRoleAsync(user, PandaUser.AdminRole);
        ActAs(controller, user.Id, "self-demote");

        var problem = Assert.IsType<ObjectResult>(
            await controller.UpdateRoles(user.Id, new AdminUserRolesRequest([]), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        // 角色未动、无吊销无审计。
        Assert.Contains(PandaAuthRoles.Admin,
            await provider.GetRequiredService<UserService>().GetRolesAsync(user));
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task UpdateRoles_RejectsUnknownRole()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "unknown-role");

        var problem = Assert.IsType<ObjectResult>(
            await controller.UpdateRoles(user.Id, new AdminUserRolesRequest(["nope"]), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task UpdateRoles_Idempotent_NoRevocationNoAudit()
    {
        var (controller, provider, revoker) = Create();
        await EnsureAdminRoleAsync(provider);
        var user = await SeedUserAsync(provider, "role-same");
        await provider.GetRequiredService<UserService>().AddToRoleAsync(user, PandaUser.AdminRole);

        var detail = DetailOf(await controller.UpdateRoles(user.Id, new AdminUserRolesRequest([PandaAuthRoles.Admin]), CancellationToken.None));

        Assert.Equal([PandaAuthRoles.Admin], detail.Roles);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task UpdateRoles_CaseVariant_IsIdempotent()
    {
        var (controller, provider, revoker) = Create();
        await EnsureAdminRoleAsync(provider);
        var user = await SeedUserAsync(provider, "role-case");
        await provider.GetRequiredService<UserService>().AddToRoleAsync(user, PandaUser.AdminRole);

        // 角色名比较与 Identity 的规范化一致（大小写不敏感）：变体不得把幂等请求折进增删路径。
        var detail = DetailOf(await controller.UpdateRoles(user.Id, new AdminUserRolesRequest(["ADMIN"]), CancellationToken.None));

        Assert.Equal([PandaAuthRoles.Admin], detail.Roles);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task UpdateRoles_OnDeletedAccount_IsRejected()
    {
        var (controller, provider, revoker) = Create();
        await EnsureAdminRoleAsync(provider);
        var user = await SeedUserAsync(provider, "deleted-roles", status: UserStatus.Deleted);

        var problem = Assert.IsType<ObjectResult>(
            await controller.UpdateRoles(user.Id, new AdminUserRolesRequest([PandaAuthRoles.Admin]), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    // ---- 解锁（Unlock） ----

    [Fact]
    public async Task Unlock_ClearsLockoutAndFailedCount_Audits()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "locked-out");
        var manager = provider.GetRequiredService<UserService>();
        await manager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(5));
        user.AccessFailedCount = 3;
        await manager.UpdateAsync(user);

        var detail = DetailOf(await controller.Unlock(user.Id, CancellationToken.None));

        Assert.Null(detail.LockoutEnd);
        Assert.Equal(0, detail.AccessFailedCount);
        // 解锁不吊销令牌：锁定只挡新登录，不使既有令牌失效。
        Assert.Empty(revoker.RevokedUsers);
        Assert.Equal(AdminAuditAction.UserUnlock, SingleAudit(provider).Action);
    }

    [Fact]
    public async Task Unlock_IdempotentWhenNotLocked()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "not-locked");

        DetailOf(await controller.Unlock(user.Id, CancellationToken.None));

        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    // ---- 资料编辑（UpdateProfile） ----

    [Fact]
    public async Task UpdateProfile_UpdatesNicknameAndRegion_Audits()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "profile-edit");

        var detail = DetailOf(await controller.UpdateProfile(
            user.Id, new AdminUserProfileRequest(Email: null, Nickname: "新昵称", Region: "cn-sh"), CancellationToken.None));

        Assert.Equal("新昵称", detail.Nickname);
        Assert.Equal("cn-sh", detail.Region);
        Assert.Equal([user.Id], revoker.RevokedUsers);
        var entry = SingleAudit(provider);
        Assert.Equal(AdminAuditAction.UserUpdateProfile, entry.Action);
        Assert.Contains("nicknameChanged\":true", entry.Detail);
        Assert.Contains("emailChanged\":false", entry.Detail);
    }

    [Fact]
    public async Task UpdateProfile_EmailChangeResetsConfirmation()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "email-change", "old@example.com");
        var manager = provider.GetRequiredService<UserService>();
        await manager.FindByIdAsync(user.Id);
        user.EmailConfirmed = true;
        await manager.UpdateAsync(user);

        var detail = DetailOf(await controller.UpdateProfile(
            user.Id, new AdminUserProfileRequest(Email: "new@example.com", Nickname: null, Region: null), CancellationToken.None));

        Assert.Equal("new@example.com", detail.Email);
        Assert.False(detail.EmailConfirmed);
        Assert.Equal([user.Id], revoker.RevokedUsers);
        Assert.Contains("emailChanged\":true", SingleAudit(provider).Detail);
    }

    [Fact]
    public async Task UpdateProfile_ClearingEmailResetsConfirmation()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "email-clear", "gone@example.com");
        // 预置已验证：清空邮箱必须连带重置验证标记，否则断言空洞。
        var manager = provider.GetRequiredService<UserService>();
        user.EmailConfirmed = true;
        await manager.UpdateAsync(user);

        var detail = DetailOf(await controller.UpdateProfile(
            user.Id, new AdminUserProfileRequest(Email: null, Nickname: null, Region: null), CancellationToken.None));

        Assert.Null(detail.Email);
        Assert.False(detail.EmailConfirmed);
        Assert.Equal([user.Id], revoker.RevokedUsers);
    }

    [Fact]
    public async Task UpdateProfile_OnDeletedAccount_IsRejected()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "deleted-profile", status: UserStatus.Deleted);

        var problem = Assert.IsType<ObjectResult>(
            await controller.UpdateProfile(
                user.Id, new AdminUserProfileRequest(Email: "x@example.com", Nickname: null, Region: null), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task UpdateProfile_Idempotent_NoRevocationNoAudit()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "profile-same", "same@example.com");

        DetailOf(await controller.UpdateProfile(
            user.Id, new AdminUserProfileRequest(Email: "same@example.com", Nickname: null, Region: null), CancellationToken.None));

        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    // ---- 重置两步验证（ResetTwoFactor） ----

    [Fact]
    public async Task ResetTwoFactor_EnabledAccountClearsBlockAndRevokesSessions()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "two-fa");
        user.TwoFactorEnabled = true;
        await provider.GetRequiredService<UserService>().UpdateAsync(user);
        var stampBefore = user.SecurityStamp;

        var detail = DetailOf(await controller.ResetTwoFactor(user.Id, CancellationToken.None));

        Assert.False(detail.TwoFactorEnabled);
        Assert.False(user.TwoFactorEnabled);
        Assert.NotEqual(stampBefore, user.SecurityStamp);
        Assert.Equal([user.Id], revoker.RevokedUsers);
    }

    [Fact]
    public async Task ResetTwoFactor_WhenLegacyFlagDisabled_StillRevokesSessionsAndWritesRecoveryAudit()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "no-two-fa");

        DetailOf(await controller.ResetTwoFactor(user.Id, CancellationToken.None));

        Assert.Equal([user.Id], revoker.RevokedUsers);
        Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().MfaRecoveryEvents.AsEnumerable());
        Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    // ---- 注销（Deactivate，终态） ----

    [Fact]
    public async Task Deactivate_WithMatchingConfirmName_DeactivatesRevokesAudits()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "deactivate-me");
        var stampBefore = user.SecurityStamp;

        var detail = DetailOf(await controller.Deactivate(
            user.Id, new AdminDeactivateRequest("deactivate-me"), CancellationToken.None));

        Assert.Equal(UserStatus.Deleted, detail.Status);
        Assert.NotEqual(stampBefore, user.SecurityStamp);
        Assert.Equal([user.Id], revoker.RevokedUsers);
        var entry = SingleAudit(provider);
        Assert.Equal(AdminAuditAction.UserDeactivate, entry.Action);
        Assert.Contains("Active", entry.Detail);
    }

    [Fact]
    public async Task Deactivate_RejectsWrongConfirmName()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "confirm-name");

        var problem = Assert.IsType<ObjectResult>(
            await controller.Deactivate(user.Id, new AdminDeactivateRequest("wrong-name"), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        Assert.Equal(UserStatus.Active,
            (await provider.GetRequiredService<UserService>().FindByIdAsync(user.Id))!.Status);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task Deactivate_RejectsSelf()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "self-deactivate");
        ActAs(controller, user.Id, "self-deactivate");

        var problem = Assert.IsType<ObjectResult>(
            await controller.Deactivate(user.Id, new AdminDeactivateRequest("self-deactivate"), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);

        Assert.Equal(UserStatus.Active,
            (await provider.GetRequiredService<UserService>().FindByIdAsync(user.Id))!.Status);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task Deactivate_IdempotentForAlreadyDeleted()
    {
        var (controller, provider, revoker) = Create();
        var user = await SeedUserAsync(provider, "already-deleted", status: UserStatus.Deleted);

        var detail = DetailOf(await controller.Deactivate(
            user.Id, new AdminDeactivateRequest("already-deleted"), CancellationToken.None));

        Assert.Equal(UserStatus.Deleted, detail.Status);
        Assert.Empty(revoker.RevokedUsers);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }
}
