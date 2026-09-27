using System.Security.Claims;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.Management;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// Management API 作用域门禁纯函数断言：audience 与 scope 缺一不可，且各自兼容两种载体——
/// OpenIddict 私有 claim（oi_aud/oi_scp，验证管线富化路径）与标准 aud/scope claim
/// （自包含 JWT/JWE 令牌直接解出的路径）。e2e 在隔离 PostgreSQL 上验证真实令牌走向。
/// </summary>
public class MgmtApiAuthorizationTests
{
    private static ClaimsPrincipal Principal(params Claim[] claims)
        => new(new ClaimsIdentity(claims, "TestBearer"));

    [Fact]
    public void PrivateClaims_Pass()
    {
        var principal = Principal(
            new Claim(Claims.Private.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.True(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void StandardClaims_Pass()
    {
        // 自包含 JWE 访问令牌验证出的 principal 携带标准 aud/scope——必须放行。
        var principal = Principal(
            new Claim(Claims.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.True(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void StandardSpaceSeparatedScope_Passes()
    {
        // OpenIddict 也会把 scope 合成单个空格分隔 claim。
        var principal = Principal(
            new Claim(Claims.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Scope, $"{MgmtApiAuthorization.ClientsReadScope} {MgmtApiAuthorization.UsersReadScope}"));

        Assert.True(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void MissingAudience_Fails_EvenWithScope()
    {
        // 只带 scope 不带 audience：可能为其他资源签发，一律拒绝。
        var principal = Principal(new Claim(Claims.Private.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.False(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void WrongAudience_Fails()
    {
        var principal = Principal(
            new Claim(Claims.Audience, "fleet-api"),
            new Claim(Claims.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.False(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void MissingScope_Fails_EvenWithAudience()
    {
        var principal = Principal(new Claim(Claims.Audience, MgmtApiAuthorization.Audience));

        Assert.False(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void WrongScope_Fails()
    {
        var principal = Principal(
            new Claim(Claims.Private.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.ClientsReadScope));

        Assert.False(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void MultiplePrivateScopeClaims_MatchingOne_Passes()
    {
        // OpenIddict 把 scope 集合展开为多个 oi_scp claim；命中任一即满足。
        var principal = Principal(
            new Claim(Claims.Private.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.ClientsReadScope),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.True(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }
}
