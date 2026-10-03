using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public class AuthorizationTimeClaimsTests
{
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
