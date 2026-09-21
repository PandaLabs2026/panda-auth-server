using System.Security.Claims;
using PandaAuth.Server.Infrastructure.Security;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// 签发给 Access Token 的声明集合属对外契约：角色只在客户端申请了 roles scope 时才写入 AT。
///
/// 与 <see cref="AuthorizationUserinfoTests"/> 的分工：那个文件测 **userinfo 的输出侧**是否有
/// scope 守卫（合成一个已含角色的 AT 主体）；本文件测 **AT 的签发侧**是否根本不写入角色 ——
/// 两者独立，缺任一侧都会让未申请 roles 的客户端读到角色（经 AT 载荷或经内省）。
/// </summary>
public class AuthorizationTokenClaimsTests
{
    [Fact]
    public async Task Principal_WithoutRolesScope_OmitsRoleClaims()
    {
        using var provider = TestUserStoreHost.Create();
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        var user = await SeedUserWithRolesAsync(provider, "admin", "user");

        var principal = await controller.CreatePrincipalAsync(user, [Scopes.OpenId, Scopes.Profile]);

        Assert.DoesNotContain(principal.Claims, claim => claim.Type == Claims.Role);
    }

    [Fact]
    public async Task Principal_WithRolesScope_IncludesRoleClaims()
    {
        using var provider = TestUserStoreHost.Create();
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        var user = await SeedUserWithRolesAsync(provider, "admin", "user");

        var principal = await controller.CreatePrincipalAsync(user, [Scopes.OpenId, Scopes.Roles]);

        Assert.Equal(
            ["admin", "user"],
            principal.Claims
                .Where(claim => claim.Type == Claims.Role)
                .Select(claim => claim.Value)
                .OrderBy(value => value));
    }

    [Fact]
    public async Task Principal_AlwaysCarriesSubjectAndScopes()
    {
        using var provider = TestUserStoreHost.Create();
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        var user = await SeedUserWithRolesAsync(provider, "admin");

        var principal = await controller.CreatePrincipalAsync(user, [Scopes.OpenId]);

        Assert.Equal(user.Id, principal.GetClaim(Claims.Subject));
        Assert.Equal([Scopes.OpenId], principal.GetScopes().ToArray());
    }

    [Fact]
    public async Task Principal_OnlyIncludesCustomClaimsWhenTheirScopeIsRequested()
    {
        using var provider = TestUserStoreHost.Create();
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        var user = await SeedUserWithRolesAsync(provider, "user");
        var claims = provider.GetRequiredService<ClaimsPolicyService>();
        Assert.True((await claims.AddUserClaimAsync(user.Id, "panda:tenant", "tenant-a", "api")).Succeeded);

        var withoutScope = await controller.CreatePrincipalAsync(user, [Scopes.OpenId]);
        var withScope = await controller.CreatePrincipalAsync(user, [Scopes.OpenId, "api"]);

        Assert.DoesNotContain(withoutScope.Claims, claim => claim.Type == "panda:tenant");
        Assert.Contains(withScope.Claims, claim => claim.Type == "panda:tenant" && claim.Value == "tenant-a");
    }

    [Fact]
    public async Task ClaimsPolicy_RejectsReservedAndUnnamespacedClaims()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await SeedUserWithRolesAsync(provider, "user");
        var claims = provider.GetRequiredService<ClaimsPolicyService>();

        Assert.False((await claims.AddUserClaimAsync(user.Id, "role", "admin", "roles")).Succeeded);
        Assert.False((await claims.AddUserClaimAsync(user.Id, "tenant", "tenant-a", "api")).Succeeded);
    }

    private static async Task<PandaUser> SeedUserWithRolesAsync(IServiceProvider provider, params string[] roles)
    {
        var roleManager = provider.GetRequiredService<RoleService>();
        foreach (var role in roles)
        {
            if (await roleManager.FindByNameAsync(role) is null)
            {
                await roleManager.CreateAsync(new PandaRole { Name = role });
            }
        }

        var userManager = provider.GetRequiredService<UserService>();
        var user = new PandaUser
        {
            UserName = "alice@example.com",
            Email = "alice@example.com",
            Status = UserStatus.Active,
        };
        await userManager.CreateAsync(user);
        await userManager.AddToRolesAsync(user, roles);

        return user;
    }
}
