using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PandaAuth.Server.Features.Authorization;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// userinfo 最小披露回归：角色只在客户端申请了 roles scope 时返回。
/// 本文件测的是 **userinfo 的输出侧**（合成一个已含角色的 AT 主体，验证无 scope 时不回显）；
/// **签发侧**（CreatePrincipalAsync 是否把角色写进 AT）见 <see cref="AuthorizationTokenClaimsTests"/>。
/// 两侧都需要守卫：只守输出侧时，未申请 roles 的客户端仍能从 AT 载荷或内省结果读到角色。
/// </summary>
public class AuthorizationUserinfoTests
{
    [Fact]
    public async Task Userinfo_WithoutRolesScope_OmitsRoleClaims()
    {
        var response = await InvokeUserinfoAsync([Scopes.OpenId, Scopes.Profile]);

        Assert.True(response.ContainsKey(Claims.Subject));
        Assert.False(response.ContainsKey(Claims.Role));
    }

    [Fact]
    public async Task Userinfo_WithRolesScope_ReturnsRoleClaims()
    {
        var response = await InvokeUserinfoAsync([Scopes.OpenId, Scopes.Profile, Scopes.Roles]);

        Assert.Equal(new[] { "admin", "user" }, Assert.IsType<string[]>(response[Claims.Role]));
    }

    [Fact]
    public async Task Userinfo_WithRolesScopeButNoRoles_OmitsRoleClaims()
    {
        var response = await InvokeUserinfoAsync([], [Scopes.OpenId, Scopes.Roles]);

        Assert.False(response.ContainsKey(Claims.Role));
    }

    private static Task<Dictionary<string, object?>> InvokeUserinfoAsync(string[] scopes)
        => InvokeUserinfoAsync(["admin", "user"], scopes);

    private static async Task<Dictionary<string, object?>> InvokeUserinfoAsync(string[] roles, string[] scopes)
    {
        using var provider = TestUserStoreHost.Create();
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        controller.ControllerContext.HttpContext.RequestServices = BuildAuthenticationServices(
            CreateAccessTokenPrincipal(roles, scopes));

        var result = await controller.Userinfo();

        var ok = Assert.IsType<OkObjectResult>(result);
        return Assert.IsType<Dictionary<string, object?>>(ok.Value);
    }

    /// <summary>还原访问令牌主体的关键部分：sub/name 声明 + scopes（oi_scp）+ 角色声明。</summary>
    private static ClaimsPrincipal CreateAccessTokenPrincipal(string[] roles, string[] scopes)
    {
        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, "user-1"));
        identity.AddClaim(new Claim(Claims.Name, "alice"));
        identity.AddClaims(roles.Select(role => new Claim(Claims.Role, role)));
        identity.SetScopes(scopes);

        return new ClaimsPrincipal(identity);
    }

    /// <summary>userinfo 通过 HttpContext.AuthenticateAsync(scheme) 取主体，这里替换认证服务返回票据。</summary>
    private static ServiceProvider BuildAuthenticationServices(ClaimsPrincipal principal)
    {
        var services = new ServiceCollection();
        var ticket = new AuthenticationTicket(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        services.AddSingleton<IAuthenticationService>(new StubAuthenticationService(
            AuthenticateResult.Success(ticket)));
        return services.BuildServiceProvider();
    }

    private sealed class StubAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
            => Task.FromResult(result);

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            => Task.CompletedTask;

        public Task SignInAsync(
            HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
            => Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            => Task.CompletedTask;
    }
}
