using System.Security.Claims;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.Management;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// Management API 作用域门禁纯函数断言：audience 与 scope 缺一不可。
/// 夹具用 OpenIddict 私有 claim（oi_aud/oi_scp）——验证管线对令牌做标准化后，
/// principal 上的 audience/scope 就落在这两个 claim 上（与 HasAudience/HasScope 扩展一致）。
/// </summary>
public class MgmtApiAuthorizationTests
{
    private static ClaimsPrincipal Principal(params Claim[] claims)
        => new(new ClaimsIdentity(claims, "TestBearer"));

    [Fact]
    public void AudienceAndScopeBothPresent_Passes()
    {
        var principal = Principal(
            new Claim(Claims.Private.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.True(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void StandardClaimsOnly_Fails()
    {
        // 锚定 OpenIddict 语义：标准 aud/scope claim 不满足 HasAudience/HasScope——
        // 门禁依赖的是验证管线标准化后的 principal，不是原始令牌载荷。
        var principal = Principal(
            new Claim(Claims.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.False(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
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
            new Claim(Claims.Private.Audience, "fleet-api"),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.False(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }

    [Fact]
    public void MissingScope_Fails_EvenWithAudience()
    {
        var principal = Principal(new Claim(Claims.Private.Audience, MgmtApiAuthorization.Audience));

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
    public void MultipleScopeClaims_MatchingOne_Passes()
    {
        // OpenIddict 把 scope 集合展开为多个 oi_scp claim；命中任一即满足。
        var principal = Principal(
            new Claim(Claims.Private.Audience, MgmtApiAuthorization.Audience),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.ClientsReadScope),
            new Claim(Claims.Private.Scope, MgmtApiAuthorization.UsersReadScope));

        Assert.True(MgmtApiAuthorization.HasAudienceAndScope(principal, MgmtApiAuthorization.UsersReadScope));
    }
}
