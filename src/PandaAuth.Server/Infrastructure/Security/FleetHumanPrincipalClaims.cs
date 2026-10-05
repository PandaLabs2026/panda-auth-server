using System.Globalization;
using System.Security.Claims;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// Fleet 控制面的人类主体事实构造器：从 IDP 校验过的登录凭据（登录 Cookie 或 OpenIddict 票据）
/// 继承标准 auth_time 并声明 subject_type=human。绝不读取浏览器参数或请求 Header；
/// 缺失/畸形/重复的认证时间一律依赖未就绪（抛出，由上层转 invalid grant）。
/// 契约正本：元仓 docs/contracts/fleet-lifecycle-v2-proposal.md。
/// </summary>
internal static class FleetHumanPrincipalClaims
{
    /// <summary>认证时间不可信时的统一失败语义（上层据此转 invalid grant / 依赖未就绪）。</summary>
    public const string InvalidAuthenticationTimeMessage = "A valid original authentication time is required.";

    /// <summary>
    /// 从受信主体读取原始认证时间：必须恰好一条、非负整秒、不超过 DateTimeOffset 秒上限。
    /// 语义与登录 Cookie / 票据两侧的既有门禁一致，供控制器各路径共用。
    /// </summary>
    public static bool TryReadAuthenticationTime(ClaimsPrincipal? source, string claimType, out long seconds)
    {
        seconds = 0;
        var claims = source?.FindAll(claimType).Take(2).ToArray();
        return claims is { Length: 1 } &&
            long.TryParse(claims[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) &&
            seconds is >= 0 and <= 253_402_300_799;
    }

    /// <summary>构造人类主体声明（subject_type=human + 标准 auth_time 整秒）。</summary>
    public static IReadOnlyList<Claim> Build(ClaimsPrincipal? verifiedLogin, string authenticationTimeClaim)
    {
        if (!TryReadAuthenticationTime(verifiedLogin, authenticationTimeClaim, out var authenticatedAt))
        {
            throw new InvalidOperationException(InvalidAuthenticationTimeMessage);
        }

        return
        [
            new Claim(PandaAuthClaims.SubjectType, PandaAuthClaims.SubjectTypes.Human),
            new Claim(Claims.AuthenticationTime, authenticatedAt.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        ];
    }
}
