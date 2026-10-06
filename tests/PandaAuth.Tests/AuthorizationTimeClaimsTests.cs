using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public class AuthorizationTimeClaimsTests
{
    [Fact]
    public void ExceedsMaxAge_PinsBoundarySemantics()
    {
        // max_age=0：显式声明任何既有认证都不可复用，恒须重认证（OIDC 语义按「超过」取严格大于，
        // 但 0 与「恰好等于 0」无法区分，取恒真才是调用方意图）。null（未携带）不强制。
        Assert.True(AuthorizationController.ExceedsMaxAge(0, authenticatedAtSeconds: 1000, nowSeconds: 1000));
        // 严格大于：恰好在限值内（含恰好等于 max_age）不强制，超过 1 秒即强制。
        Assert.False(AuthorizationController.ExceedsMaxAge(60, 1000, 1060));
        Assert.True(AuthorizationController.ExceedsMaxAge(60, 1000, 1061));
        // 未携带 max_age 的请求不做年龄约束（兼容既有静默续签流）。
        Assert.False(AuthorizationController.ExceedsMaxAge(null, 0, long.MaxValue));
    }

    [Theory]
    [InlineData("0", "0")]
    [InlineData("1700000000", "1700000000")]
    [InlineData("253402300799", "253402300799")]
    public async Task TrustedCookieTime_IsNumericAndDestinedForIdentityToken(string raw, string expected)
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        var principal = await TestUserStoreHost.CreateAuthorizationController(provider)
            .CreatePrincipalAsync(user, [Scopes.OpenId, Scopes.Profile], Source(raw));

        var time = Assert.Single(principal.FindAll(Claims.AuthenticationTime));
        Assert.Equal(expected, time.Value);
        Assert.Equal(ClaimValueTypes.Integer64, time.ValueType);
        Assert.Contains(Destinations.IdentityToken, time.GetDestinations());
        Assert.DoesNotContain(principal.Claims, c => c.Type == LoginSessionService.AuthenticatedAtClaim);
        Assert.Contains(Destinations.IdentityToken, principal.FindFirst(Claims.Name)!.GetDestinations());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("no-time")]
    [InlineData("-1")]
    [InlineData("253402300800")]
    [InlineData("9223372036854775808")]
    [InlineData("1700000000.5")]
    public async Task MissingOrInvalidTrustedCookieTime_CannotIssueHumanPrincipal(string? raw)
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TestUserStoreHost.CreateAuthorizationController(provider)
                .CreatePrincipalAsync(user, [Scopes.OpenId], Source(raw)));
    }

    [Fact]
    public async Task DuplicateTrustedCookieTime_IsRejectedEvenWhenValuesAgree()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        var source = Source("1700000000");
        ((ClaimsIdentity)source.Identity!).AddClaim(new Claim(LoginSessionService.AuthenticatedAtClaim, "1700000000"));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TestUserStoreHost.CreateAuthorizationController(provider)
                .CreatePrincipalAsync(user, [Scopes.OpenId], source));
    }

    [Fact]
    public async Task ProfileNameIsNotDisclosedWithoutProfileScope()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        var principal = await TestUserStoreHost.CreateAuthorizationController(provider)
            .CreatePrincipalAsync(user, [Scopes.OpenId], Source("1700000000"));
        Assert.Equal("time-user", principal.GetClaim(Claims.Name));
        Assert.DoesNotContain(Destinations.IdentityToken, principal.FindFirst(Claims.Name)!.GetDestinations());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HistoricalPolicyRows_CannotOverrideTrustedTimeOrProfileName(bool roleRow)
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        var role = new PandaRole { Name = "time-role" };
        await provider.GetRequiredService<RoleService>().CreateAsync(role);
        await provider.GetRequiredService<UserService>().AddToRolesAsync(user, [role.Name]);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        foreach (var type in new[] { Claims.AuthenticationTime, Claims.Name, LoginSessionService.AuthenticatedAtClaim })
        {
            if (roleRow) db.RoleClaims.Add(new PandaRoleClaim { RoleId = role.Id, ClaimType = type, ClaimValue = "999", Scope = Scopes.Profile });
            else db.UserClaims.Add(new PandaUserClaim { UserId = user.Id, ClaimType = type, ClaimValue = "999", Scope = Scopes.Profile });
        }
        await db.SaveChangesAsync();
        var principal = await TestUserStoreHost.CreateAuthorizationController(provider)
            .CreatePrincipalAsync(user, [Scopes.OpenId, Scopes.Profile], Source("1700000000"));
        Assert.Equal("1700000000", Assert.Single(principal.FindAll(Claims.AuthenticationTime)).Value);
        Assert.Equal("time-user", Assert.Single(principal.FindAll(Claims.Name)).Value);
        Assert.Empty(principal.FindAll(LoginSessionService.AuthenticatedAtClaim));
    }

    internal static ClaimsPrincipal Source(string? raw)
        => new(new ClaimsIdentity(raw is null ? [] : [new Claim(LoginSessionService.AuthenticatedAtClaim, raw)], "verified-test-cookie"));

    private static async Task<PandaUser> UserAsync(IServiceProvider provider)
    {
        var user = new PandaUser { UserName = "time-user" };
        Assert.True((await provider.GetRequiredService<UserService>().CreateAsync(user)).Succeeded);
        return user;
    }
}
