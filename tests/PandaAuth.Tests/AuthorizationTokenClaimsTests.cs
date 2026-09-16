using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
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
        using var provider = TestIdentityHost.Create();
        var controller = TestIdentityHost.CreateAuthorizationController(provider);
        var user = await SeedUserWithRolesAsync(provider, "admin", "user");

        var principal = await controller.CreatePrincipalAsync(user, [Scopes.OpenId, Scopes.Profile]);

        Assert.DoesNotContain(principal.Claims, claim => claim.Type == Claims.Role);
    }

    [Fact]
    public async Task Principal_WithRolesScope_IncludesRoleClaims()
    {
        using var provider = TestIdentityHost.Create();
        var controller = TestIdentityHost.CreateAuthorizationController(provider);
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
        using var provider = TestIdentityHost.Create();
        var controller = TestIdentityHost.CreateAuthorizationController(provider);
        var user = await SeedUserWithRolesAsync(provider, "admin");

        var principal = await controller.CreatePrincipalAsync(user, [Scopes.OpenId]);

        Assert.Equal(user.Id, principal.GetClaim(Claims.Subject));
        Assert.Equal([Scopes.OpenId], principal.GetScopes().ToArray());
    }

    private static async Task<PandaAuthUser> SeedUserWithRolesAsync(IServiceProvider provider, params string[] roles)
    {
        var roleManager = provider.GetRequiredService<RoleManager<PandaAuthRole>>();
        foreach (var role in roles)
        {
            if (await roleManager.FindByNameAsync(role) is null)
            {
                await roleManager.CreateAsync(new PandaAuthRole { Name = role });
            }
        }

        var userManager = provider.GetRequiredService<UserManager<PandaAuthUser>>();
        var user = new PandaAuthUser
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
