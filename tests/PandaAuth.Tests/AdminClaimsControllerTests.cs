using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class AdminClaimsControllerTests
{
    [Fact]
    public async Task RoleDirectory_UsesCaseInsensitiveContainsAndStableNameOrdering()
    {
        var (provider, _) = AdminTestHost.Create();
        var roles = provider.GetRequiredService<RoleService>();
        foreach (var name in new[] { "zeta", "Admin-Read", "admin-write" })
            Assert.True((await roles.CreateAsync(new PandaRole { Name = name })).Succeeded);

        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var result = Assert.IsType<OkObjectResult>(await controller.List("ADMIN", 1, 20, CancellationToken.None));
        var page = Assert.IsType<AdminPageResult<AdminRoleSummary>>(result.Value);
        Assert.Equal(["Admin-Read", "admin-write"], page.Items.Select(item => item.Name));
    }

    [Theory]
    [InlineData(0, 20, 1, 20)]
    [InlineData(1, 999, 1, 50)]
    public async Task RoleDirectory_ClampsPageArguments(int page, int pageSize, int expectedPage, int expectedSize)
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var result = Assert.IsType<OkObjectResult>(await controller.List(null, page, pageSize, CancellationToken.None));
        var response = Assert.IsType<AdminPageResult<AdminRoleSummary>>(result.Value);
        Assert.Equal(expectedPage, response.Page);
        Assert.Equal(expectedSize, response.PageSize);
    }

    [Fact]
    public async Task RoleDirectory_NormalizesUnicodeQueryLikeRolePersistence()
    {
        var (provider, _) = AdminTestHost.Create();
        var role = new PandaRole { Name = "Café-Read" };
        Assert.True((await provider.GetRequiredService<RoleService>().CreateAsync(role)).Succeeded);
        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var result = Assert.IsType<OkObjectResult>(await controller.List("cafe\u0301", 1, 20, CancellationToken.None));
        var page = Assert.IsType<AdminPageResult<AdminRoleSummary>>(result.Value);
        Assert.Equal(["Café-Read"], page.Items.Select(item => item.Name));
    }

    [Fact]
    public async Task RoleDirectory_PaginatesStableOrderingAndReportsTotal()
    {
        var (provider, _) = AdminTestHost.Create();
        var roles = provider.GetRequiredService<RoleService>();
        foreach (var name in new[] { "gamma", "delta", "beta", "alpha" })
            Assert.True((await roles.CreateAsync(new PandaRole { Name = name })).Succeeded);
        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var result = Assert.IsType<OkObjectResult>(await controller.List(null, 2, 2, CancellationToken.None));
        var page = Assert.IsType<AdminPageResult<AdminRoleSummary>>(result.Value);
        Assert.Equal(4, page.Total);
        Assert.Equal(["delta", "gamma"], page.Items.Select(item => item.Name));
    }

    [Fact]
    public async Task RoleDirectory_FiltersBeforeCountingAndReturnsEmptyPagePastEnd()
    {
        var (provider, _) = AdminTestHost.Create();
        var roles = provider.GetRequiredService<RoleService>();
        foreach (var name in new[] { "admin-read", "admin-write", "auditor" })
            Assert.True((await roles.CreateAsync(new PandaRole { Name = name })).Succeeded);
        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var filtered = Assert.IsType<OkObjectResult>(await controller.List(" admin ", 2, 1, CancellationToken.None));
        var filteredPage = Assert.IsType<AdminPageResult<AdminRoleSummary>>(filtered.Value);
        Assert.Equal(2, filteredPage.Total);
        Assert.Equal(["admin-write"], filteredPage.Items.Select(item => item.Name));

        var pastEnd = Assert.IsType<OkObjectResult>(await controller.List("admin", 3, 1, CancellationToken.None));
        var pastEndPage = Assert.IsType<AdminPageResult<AdminRoleSummary>>(pastEnd.Value);
        Assert.Equal(2, pastEndPage.Total);
        Assert.Empty(pastEndPage.Items);
    }

    [Fact]
    public async Task RoleDirectory_ReturnsEmptyPageForMaximumLegalPageNumber()
    {
        var (provider, _) = AdminTestHost.Create();
        Assert.True((await provider.GetRequiredService<RoleService>().CreateAsync(
            new PandaRole { Name = "first-role" })).Succeeded);
        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var result = Assert.IsType<OkObjectResult>(await controller.List(null, int.MaxValue, 20, CancellationToken.None));
        var page = Assert.IsType<AdminPageResult<AdminRoleSummary>>(result.Value);
        Assert.Equal(int.MaxValue, page.Page);
        Assert.Equal(1, page.Total);
        Assert.Empty(page.Items);
    }

    [Fact]
    public void RoleDirectory_RequiresAdminValidationAuthorization()
    {
        Assert.IsType<RequireConfirmedEmailAttribute>(Attribute.GetCustomAttribute(
            typeof(AdminRolesController), typeof(RequireConfirmedEmailAttribute)));
        var authorize = Assert.IsType<AuthorizeAttribute>(Attribute.GetCustomAttribute(
            typeof(AdminRolesController), typeof(AuthorizeAttribute)));
        Assert.Equal(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, authorize.AuthenticationSchemes);
        Assert.Equal(AdminApiAuthorization.PolicyName, authorize.Policy);
    }

    [Fact]
    public async Task RoleDirectory_ProjectsOnlyRoleIdAndName()
    {
        var (provider, _) = AdminTestHost.Create();
        var role = new PandaRole { Name = "role-summary" };
        Assert.True((await provider.GetRequiredService<RoleService>().CreateAsync(role)).Succeeded);
        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var result = Assert.IsType<OkObjectResult>(await controller.List(null, 1, 20, CancellationToken.None));
        var summary = Assert.Single(Assert.IsType<AdminPageResult<AdminRoleSummary>>(result.Value).Items);
        Assert.Equal(role.Id, summary.Id);
        Assert.Equal("role-summary", summary.Name);
        Assert.Equal(["Id", "Name"], summary.GetType().GetProperties().Select(property => property.Name).Order());
    }

    [Fact]
    public async Task RoleDirectory_ReturnsEmptyPageWhenQueryHasNoMatch()
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new AdminRolesController(provider.GetRequiredService<PandaAuthDbContext>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };

        var result = Assert.IsType<OkObjectResult>(await controller.List("absent", 1, 20, CancellationToken.None));
        var page = Assert.IsType<AdminPageResult<AdminRoleSummary>>(result.Value);
        Assert.Empty(page.Items);
        Assert.Equal(0, page.Total);
    }

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
        Assert.Equal("/admin-api/roles", PandaAuthAdminApi.Roles);
        var summary = new AdminRoleSummary("role-1", "admin");
        Assert.Equal("admin", summary.Name);

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
