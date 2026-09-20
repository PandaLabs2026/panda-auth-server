using System.Globalization;
using System.Security.Claims;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public static class RecentMfaRequirement
{
    public static bool HasValidMfa(ClaimsPrincipal principal, DateTimeOffset now, TimeSpan maximumAge)
        => HasMethod(principal, MfaClaimTypes.WebAuthn, MfaClaimTypes.Totp) && IsWithinAge(principal, now, maximumAge);

    public static bool HasRecentWebAuthn(ClaimsPrincipal principal, DateTimeOffset now, TimeSpan maximumAge)
        => HasMethod(principal, MfaClaimTypes.WebAuthn) && IsWithinAge(principal, now, maximumAge);

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
