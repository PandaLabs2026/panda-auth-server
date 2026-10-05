using System.Globalization;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// Fleet 控制面人类主体单元契约：subject_type=human + 标准 auth_time 只从 IDP 校验过的
/// 登录凭据继承（真实协议行为——refresh/MFA 标记不前移、畸形票据 invalid grant——由
/// PortalAuthTimeProtocolTests 与 FleetIntrospectionTests 的真实管线覆盖）；本文件锁定
/// 构造器语义与 AT Destination——introspection 结果从 AT 主体投影，缺 AT destination
/// 就等于控制面永远读不到该 claim。
/// </summary>
public class FleetHumanPrincipalTests
{
    [Fact]
    public async Task CreatePrincipalAsync_EmitsHumanSubjectTypeAndInheritedIntegerAuthTime()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        var principal = await TestUserStoreHost.CreateAuthorizationController(provider)
            .CreatePrincipalAsync(user, [Scopes.OpenId], TrustedSource("1700000000"));

        Assert.Equal(PandaAuthClaims.SubjectTypes.Human,
            principal.FindFirst(PandaAuthClaims.SubjectType)?.Value);
        var time = Assert.Single(principal.FindAll(Claims.AuthenticationTime));
        Assert.Equal("1700000000", time.Value);
        Assert.Equal(ClaimValueTypes.Integer64, time.ValueType);
    }

    [Fact]
    public async Task AuthTimeAndSubjectType_AreDestinedForAccessToken_IntrospectionProjection()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        var principal = await TestUserStoreHost.CreateAuthorizationController(provider)
            .CreatePrincipalAsync(user, [Scopes.OpenId], TrustedSource("1700000000"));

        Assert.Contains(Destinations.AccessToken, principal.FindFirst(Claims.AuthenticationTime)!.GetDestinations());
        Assert.Contains(Destinations.IdentityToken, principal.FindFirst(Claims.AuthenticationTime)!.GetDestinations());
        Assert.Contains(Destinations.AccessToken, principal.FindFirst(PandaAuthClaims.SubjectType)!.GetDestinations());
    }

    [Fact]
    public async Task Build_FromRealLoginSession_InheritsAuthenticatedAtWithoutMovingIt()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await UserAsync(provider);
        var login = await TestUserStoreHost.AuthenticatedPrincipalAsync(provider, user);
        var expected = long.Parse(login.FindFirst(LoginSessionService.AuthenticatedAtClaim)!.Value,
            CultureInfo.InvariantCulture);

        var claims = FleetHumanPrincipalClaims.Build(login, LoginSessionService.AuthenticatedAtClaim);

        Assert.Equal(PandaAuthClaims.SubjectTypes.Human,
            claims.Single(claim => claim.Type == PandaAuthClaims.SubjectType).Value);
        var time = claims.Single(claim => claim.Type == Claims.AuthenticationTime);
        Assert.Equal(expected.ToString(CultureInfo.InvariantCulture), time.Value);
        Assert.Equal(ClaimValueTypes.Integer64, time.ValueType);
    }

    [Fact]
    public void Build_WithTicketSourcedStandardClaim_AcceptsStandardAuthTimeClaimType()
    {
        var ticket = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(Claims.AuthenticationTime, "1700000000", ClaimValueTypes.Integer64)], "oidc-ticket"));

        Assert.Equal("1700000000",
            FleetHumanPrincipalClaims.Build(ticket, Claims.AuthenticationTime)
                .Single(claim => claim.Type == Claims.AuthenticationTime).Value);
    }

    [Fact]
    public void Build_WithMissingAuthenticationTime_FailsClosed()
    {
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity("anonymous"));

        var exception = Assert.Throws<InvalidOperationException>(
            () => FleetHumanPrincipalClaims.Build(anonymous, LoginSessionService.AuthenticatedAtClaim));

        Assert.Equal(FleetHumanPrincipalClaims.InvalidAuthenticationTimeMessage, exception.Message);
    }

    [Theory]
    [InlineData("not-a-time")]
    [InlineData("-1")]
    [InlineData("1700000000.5")]
    [InlineData("253402300800")]
    [InlineData("9223372036854775808")]
    [InlineData("")]
    public void Build_WithMalformedAuthenticationTime_FailsClosed(string raw)
    {
        var source = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(LoginSessionService.AuthenticatedAtClaim, raw)], "verified-test-cookie"));

        Assert.Throws<InvalidOperationException>(
            () => FleetHumanPrincipalClaims.Build(source, LoginSessionService.AuthenticatedAtClaim));
    }

    [Fact]
    public void Build_WithDuplicateAuthenticationTime_FailsClosedEvenWhenValuesAgree()
    {
        var source = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(LoginSessionService.AuthenticatedAtClaim, "1700000000"),
            new Claim(LoginSessionService.AuthenticatedAtClaim, "1700000000"),
        ], "verified-test-cookie"));

        Assert.Throws<InvalidOperationException>(
            () => FleetHumanPrincipalClaims.Build(source, LoginSessionService.AuthenticatedAtClaim));
    }

    private static ClaimsPrincipal TrustedSource(string raw)
        => new(new ClaimsIdentity([new Claim(LoginSessionService.AuthenticatedAtClaim, raw)], "verified-test-cookie"));

    private static async Task<PandaUser> UserAsync(IServiceProvider provider)
    {
        var user = new PandaUser { UserName = "fleet-time-user" };
        Assert.True((await provider.GetRequiredService<UserService>().CreateAsync(user)).Succeeded);
        return user;
    }
}
