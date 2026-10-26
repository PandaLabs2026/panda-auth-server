using System.Globalization;
using System.Security.Claims;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public static class RecentMfaRequirement
{
    // WebAuthn 仍在方法清单里：Passkey 已退役（AUTH-DELIVERY-002），但部署切换前签发的
    // 旧令牌可能仍带 webauthn amr——8 小时窗内的存量事实按历史语义承认，不再新产生。
    public static bool HasValidMfa(ClaimsPrincipal principal, DateTimeOffset now, TimeSpan maximumAge)
        => HasMethod(principal, MfaClaimTypes.WebAuthn, MfaClaimTypes.Totp, MfaClaimTypes.RecoveryCode) && IsWithinAge(principal, now, maximumAge);

    private static bool HasMethod(ClaimsPrincipal principal, params string[] requiredMethods)
        => principal.FindAll(MfaClaimTypes.Method)
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Any(method => requiredMethods.Contains(method, StringComparer.Ordinal));

    private static bool IsWithinAge(ClaimsPrincipal principal, DateTimeOffset now, TimeSpan maximumAge)
    {
        var raw = principal.FindFirst(MfaClaimTypes.VerifiedAt)?.Value;
        DateTimeOffset verifiedAt;
        if (long.TryParse(raw, CultureInfo.InvariantCulture, out var unixSeconds) &&
            unixSeconds is >= -62_135_596_800 and <= 253_402_300_799)
        {
            verifiedAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }
        else if (!DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out verifiedAt))
        {
            return false;
        }

        return verifiedAt <= now && now - verifiedAt <= maximumAge;
    }
}
