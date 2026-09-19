using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public class AdminAuditControllerTests
{
    private static (AdminAuditController Controller, ServiceProvider Provider) Create()
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new AdminAuditController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };
        return (controller, provider);
    }

    private static async Task<PandaAuthDbContext> SeedAsync(ServiceProvider provider)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.LoginLogs.AddRange(
            new LoginLog { UserName = "alice", Succeeded = true, CreatedAt = DateTimeOffset.Parse("2026-09-01T00:00:00Z"), IpAddress = "1.1.1.1" },
            new LoginLog { UserName = "alice", Succeeded = false, FailureReason = "wrong_password", CreatedAt = DateTimeOffset.Parse("2026-09-02T00:00:00Z") },
            new LoginLog { UserName = "bob", Succeeded = true, CreatedAt = DateTimeOffset.Parse("2026-09-03T00:00:00Z") });
        db.AdminAuditLogs.AddRange(
            new AdminAuditLog { ActorUserId = "actor-1", ActorUserName = "admin", Action = AdminAuditAction.UserFreeze, TargetType = "user", TargetId = "u-1", CreatedAt = DateTimeOffset.Parse("2026-09-02T12:00:00Z") },
            new AdminAuditLog { ActorUserId = "actor-2", ActorUserName = "ops", Action = AdminAuditAction.ClientRotateSecret, TargetType = "client", TargetId = "me-web", CreatedAt = DateTimeOffset.Parse("2026-09-04T12:00:00Z") });
        await db.SaveChangesAsync();
        return db;
    }

    private static AdminPageResult<T> PageOf<T>(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return Assert.IsType<AdminPageResult<T>>(ok.Value);
    }

    [Fact]
    public async Task LoginAudit_FiltersByUserSuccessAndTimeRange()
    {
        var (controller, provider) = Create();
        await SeedAsync(provider);

        var byUser = PageOf<AdminLoginLogEntry>(await controller.Logins("ali", null, null, null, null, null, CancellationToken.None));
        Assert.Equal(2, byUser.Total);

        var bySuccess = PageOf<AdminLoginLogEntry>(await controller.Logins(null, false, null, null, null, null, CancellationToken.None));
        var failed = Assert.Single(bySuccess.Items);
        Assert.Equal("wrong_password", failed.FailureReason);

        var byRange = PageOf<AdminLoginLogEntry>(await controller.Logins(
            null, null,
            DateTimeOffset.Parse("2026-09-02T00:00:01Z"), DateTimeOffset.Parse("2026-09-03T00:00:00Z"),
            null, null, CancellationToken.None));
        Assert.Equal("bob", Assert.Single(byRange.Items).UserName);

        // 倒序：最新在前。
        var all = PageOf<AdminLoginLogEntry>(await controller.Logins(null, null, null, null, null, null, CancellationToken.None));
        Assert.Equal("bob", all.Items[0].UserName);
    }

    [Fact]
    public async Task AdminAudit_FiltersByActorActionAndTime()
    {
        var (controller, provider) = Create();
        await SeedAsync(provider);

        var byActor = PageOf<AdminAuditLogEntry>(await controller.Admin("ops", null, null, null, null, null, CancellationToken.None));
        Assert.Equal(AdminAuditAction.ClientRotateSecret, Assert.Single(byActor.Items).Action);
        Assert.Equal("me-web", byActor.Items[0].TargetId);

        var byAction = PageOf<AdminAuditLogEntry>(await controller.Admin(null, AdminAuditAction.UserFreeze, null, null, null, null, CancellationToken.None));
        Assert.Equal("u-1", Assert.Single(byAction.Items).TargetId);

        var paged = PageOf<AdminAuditLogEntry>(await controller.Admin(null, null, null, null, 1, 1, CancellationToken.None));
        Assert.Equal(2, paged.Total);
        Assert.Single(paged.Items);
        Assert.Equal(1, paged.PageSize);
    }
}

public class AdminSupportTests
{
    [Fact]
    public void PasswordGenerator_ProducesCompliantDistinctValues()
    {
        var seen = new HashSet<string>();
        for (var i = 0; i < 100; i++)
        {
            var password = AdminPasswordGenerator.Generate();
            Assert.Equal(16, password.Length);
            Assert.True(password.Any(char.IsUpper), password);
            Assert.True(password.Any(char.IsLower), password);
            Assert.True(password.Any(char.IsDigit), password);
            Assert.True(password.Any(c => !char.IsLetterOrDigit(c)), password);
            Assert.True(seen.Add(password), "100 次生成出现重复（16 字符 CSPRNG 下概率可忽略，重复即实现有误）。");
        }
    }

    [Theory]
    [InlineData(OpenIddictConstants.Permissions.Endpoints.Authorization)]
    [InlineData(OpenIddictConstants.Permissions.GrantTypes.RefreshToken)]
    [InlineData(OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access")]
    [InlineData(OpenIddictConstants.Permissions.Prefixes.Scope + "my-custom-api")]
    [InlineData(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange)]
    public void PermissionCatalog_AllowsKnownAndScpPrefixed(string permission)
        => Assert.True(PermissionCatalog.IsAllowed(permission));

    [Theory]
    [InlineData("")]
    [InlineData("gt:password")]
    [InlineData("rs:id_token")]
    [InlineData("scp:")]
    [InlineData("endpoint:authorization")]
    [InlineData("scp: with space")]
    public void PermissionCatalog_RejectsUnknownOrMalformed(string permission)
        => Assert.False(PermissionCatalog.IsAllowed(permission));

    [Fact]
    public async Task Retention_PurgesAdminAuditLogs()
    {
        // 与 LoginLogRetentionTests 同构：直接验证 admin_audit_logs 的分批删除路径。
        var (provider, _) = AdminTestHost.Create();
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.AdminAuditLogs.Add(new AdminAuditLog { ActorUserId = "a", Action = "user.freeze", CreatedAt = DateTimeOffset.Parse("2026-01-01T00:00:00Z") });
        db.AdminAuditLogs.Add(new AdminAuditLog { ActorUserId = "a", Action = "user.freeze", CreatedAt = DateTimeOffset.Parse("2026-09-01T00:00:00Z") });
        await db.SaveChangesAsync();

        var removed = await LoginLogRetentionService.PurgeAdminAuditAsync(
            db, DateTimeOffset.Parse("2026-08-01T00:00:00Z"), 500, CancellationToken.None);

        Assert.Equal(1, removed);
        Assert.Single(db.AdminAuditLogs.AsEnumerable());
    }
}
