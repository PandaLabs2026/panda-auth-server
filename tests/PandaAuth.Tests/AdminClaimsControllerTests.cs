using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class AdminClaimsControllerTests
{
    private static (AdminClaimsController Controller, ServiceProvider Provider) Create(bool withMfa = true)
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new AdminClaimsController(
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<ClaimsPolicyService>(),
            provider.GetRequiredService<AdminAuditWriter>(),
            provider.GetRequiredService<SecurityEventWriter>())
        {
            ControllerContext = new()
            {
                HttpContext = AdminTestHost.HttpContext(provider),
            },
        };
        if (!withMfa)
        {
            controller.ControllerContext.HttpContext.User = AdminTestHost.AdminPrincipalWithoutMfa();
        }
        return (controller, provider);
    }

    [Fact]
    public async Task UserClaims_CanAddListAndRemove_WithAuditAndSecurityEvent()
    {
        var (controller, provider) = Create();
        var user = new PandaUser { UserName = "claims-user" };
        Assert.True((await provider.GetRequiredService<UserService>().CreateAsync(user)).Succeeded);

        var created = Assert.IsType<CreatedResult>(await controller.AddUser(
            user.Id, new AdminClaimRequest("panda:tenant", "tenant-a", "api"), CancellationToken.None));
        var entry = Assert.IsType<AdminUserClaimEntry>(created.Value);
        Assert.Equal(PandaAuthAdminApi.UserClaim(user.Id, entry.Id), created.Location);

        var listed = Assert.IsType<OkObjectResult>(await controller.ListUser(user.Id));
        Assert.Single(Assert.IsType<AdminUserClaimEntry[]>(listed.Value));

        Assert.IsType<NoContentResult>(await controller.RemoveUser(user.Id, entry.Id, CancellationToken.None));
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().UserClaims.AsEnumerable());
        Assert.Equal(2, provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.Count());
        Assert.Equal(
            ["user.add_claim", "user.remove_claim"],
            provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents
                .OrderBy(item => item.Id).Select(item => item.EventType).ToArray());
    }

    [Fact]
    public async Task RoleClaims_CanBeManaged_WithScopeBoundCustomClaim()
    {
        var (controller, provider) = Create();
        var role = new PandaRole { Name = "claims-role" };
        Assert.True((await provider.GetRequiredService<RoleService>().CreateAsync(role)).Succeeded);

        var created = Assert.IsType<CreatedResult>(await controller.AddRole(
            role.Id, new AdminClaimRequest("panda:department", "engineering", "api"), CancellationToken.None));
        var entry = Assert.IsType<AdminRoleClaimEntry>(created.Value);
        var listed = Assert.IsType<OkObjectResult>(await controller.ListRole(role.Id));
        Assert.Equal(entry, Assert.Single(Assert.IsType<AdminRoleClaimEntry[]>(listed.Value)));

        Assert.IsType<NoContentResult>(await controller.RemoveRole(role.Id, entry.Id, CancellationToken.None));
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().RoleClaims.AsEnumerable());
    }

    [Fact]
    public async Task ClaimWrites_RequireRecentWebAuthn()
    {
        var (controller, provider) = Create(withMfa: false);
        var user = new PandaUser { UserName = "claims-no-mfa" };
        Assert.True((await provider.GetRequiredService<UserService>().CreateAsync(user)).Succeeded);

        var result = Assert.IsType<ForbidResult>(await controller.AddUser(
            user.Id, new AdminClaimRequest("panda:tenant", "tenant-a", "api"), CancellationToken.None));
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().UserClaims.AsEnumerable());
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents.AsEnumerable());
    }

    [Fact]
    public async Task ClaimDelete_CannotCrossUserBoundary()
    {
        var (controller, provider) = Create();
        var users = provider.GetRequiredService<UserService>();
        var first = new PandaUser { UserName = "claims-first" };
        var second = new PandaUser { UserName = "claims-second" };
        Assert.True((await users.CreateAsync(first)).Succeeded);
        Assert.True((await users.CreateAsync(second)).Succeeded);
        var claims = provider.GetRequiredService<ClaimsPolicyService>();
        Assert.True((await claims.AddUserClaimAsync(first.Id, "panda:tenant", "tenant-a", "api")).Succeeded);
        var claim = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().UserClaims.AsEnumerable());

        Assert.IsType<NotFoundResult>(await controller.RemoveUser(second.Id, claim.Id, CancellationToken.None));
        Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().UserClaims.AsEnumerable());
    }
}
