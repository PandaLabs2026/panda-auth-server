using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
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

    [Fact]
    public async Task Openid_Only_Discloses_Subject()
    {
        var response = await InvokeUserinfoAsync([Scopes.OpenId]);
        Assert.Equal(new[] { Claims.Subject }, response.Keys);
    }

    [Fact]
    public async Task Profile_And_Email_Are_Independently_Gated_And_Do_Not_Expand_Database_Data()
    {
        var profile = await InvokeUserinfoAsync([Scopes.OpenId, Scopes.Profile]);
        Assert.Equal("alice", profile[Claims.Name]);
        Assert.Equal("token-nickname", profile[PandaAuthClaims.Nickname]);
        Assert.False(profile.ContainsKey(Claims.Email));
        var email = await InvokeUserinfoAsync([Scopes.OpenId, Scopes.Email]);
        Assert.Equal("token@example.test", email[Claims.Email]);
        Assert.False(email.ContainsKey(Claims.Name));
        Assert.False(email.ContainsKey(PandaAuthClaims.Nickname));
    }

    [Theory]
    [InlineData(UserStatus.Frozen)]
    [InlineData(UserStatus.Deleted)]
    public async Task Inactive_User_Is_Rejected(UserStatus status)
    {
        var result = await InvokeResultAsync(CreateAccessTokenPrincipal([], [Scopes.OpenId]), status: status);
        AssertInvalidToken(result);
    }

    [Fact]
    public async Task Deleted_Row_Is_Rejected()
        => AssertInvalidToken(await InvokeResultAsync(CreateAccessTokenPrincipal([], [Scopes.OpenId]), seed: false));

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("empty")]
    [InlineData("machine")]
    [InlineData("unknown-type")]
    [InlineData("duplicate-type")]
    public async Task Invalid_Subject_Is_Not_Mapped_To_A_Human(string fault)
    {
        var principal = CreateAccessTokenPrincipal([], [Scopes.OpenId]);
        var identity = Assert.IsType<ClaimsIdentity>(principal.Identity);
        if (fault is "missing" or "empty") identity.RemoveClaim(identity.FindFirst(Claims.Subject)!);
        if (fault == "empty") identity.AddClaim(new Claim(Claims.Subject, " "));
        if (fault == "duplicate") identity.AddClaim(new Claim(Claims.Subject, "another-user"));
        if (fault == "machine") identity.AddClaim(new Claim(PandaAuthClaims.SubjectType, PandaAuthClaims.SubjectTypes.Machine));
        if (fault == "unknown-type") identity.AddClaim(new Claim(PandaAuthClaims.SubjectType, "unknown"));
        if (fault == "duplicate-type")
        {
            identity.AddClaim(new Claim(PandaAuthClaims.SubjectType, PandaAuthClaims.SubjectTypes.Human));
            identity.AddClaim(new Claim(PandaAuthClaims.SubjectType, PandaAuthClaims.SubjectTypes.Machine));
        }
        AssertInvalidToken(await InvokeResultAsync(principal));
    }

    [Fact]
    public async Task Explicit_Human_And_Legacy_Subjects_Are_Accepted()
    {
        var principal = CreateAccessTokenPrincipal([], [Scopes.OpenId]);
        Assert.IsType<OkObjectResult>(await InvokeResultAsync(principal));
        Assert.IsType<ClaimsIdentity>(principal.Identity).AddClaim(new Claim(PandaAuthClaims.SubjectType, PandaAuthClaims.SubjectTypes.Human));
        Assert.IsType<OkObjectResult>(await InvokeResultAsync(principal));
    }

    [Fact]
    public async Task Openid_Scope_Is_Required()
    {
        var result = Assert.IsType<ForbidResult>(await InvokeResultAsync(CreateAccessTokenPrincipal([], [Scopes.Profile])));
        Assert.Equal(Errors.InsufficientScope, result.Properties!.Items[OpenIddictServerAspNetCoreConstants.Properties.Error]);
    }

    private static void AssertInvalidToken(IActionResult result)
    {
        var forbidden = Assert.IsType<ForbidResult>(result);
        Assert.Equal(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme }, forbidden.AuthenticationSchemes);
        Assert.Equal(Errors.InvalidToken, forbidden.Properties!.Items[OpenIddictServerAspNetCoreConstants.Properties.Error]);
    }

    private static Task<Dictionary<string, object?>> InvokeUserinfoAsync(string[] scopes)
        => InvokeUserinfoAsync(["admin", "user"], scopes);

    private static async Task<Dictionary<string, object?>> InvokeUserinfoAsync(string[] roles, string[] scopes)
    {
        var result = await InvokeResultAsync(CreateAccessTokenPrincipal(roles, scopes));
        return Assert.IsType<Dictionary<string, object?>>(Assert.IsType<OkObjectResult>(result).Value);
    }

    private static async Task<IActionResult> InvokeResultAsync(ClaimsPrincipal principal, bool seed = true, UserStatus status = UserStatus.Active)
    {
        using var provider = TestUserStoreHost.Create();
        if (seed)
        {
            var db = provider.GetRequiredService<PandaAuthDbContext>();
            db.Users.Add(new PandaUser { Id = "user-1", UserName = "database-name", Email = "database@example.test", Nickname = "database-nickname", Status = status });
            await db.SaveChangesAsync();
        }
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        using var authentication = BuildAuthenticationServices(principal);
        controller.ControllerContext.HttpContext.RequestServices = authentication;
        return await controller.Userinfo();
    }

    /// <summary>还原访问令牌主体的关键部分：sub/name 声明 + scopes（oi_scp）+ 角色声明。</summary>
    private static ClaimsPrincipal CreateAccessTokenPrincipal(string[] roles, string[] scopes)
    {
        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, "user-1"));
        identity.AddClaim(new Claim(Claims.Name, "alice"));
        identity.AddClaim(new Claim(Claims.Email, "token@example.test"));
        identity.AddClaim(new Claim(PandaAuthClaims.Nickname, "token-nickname"));
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
