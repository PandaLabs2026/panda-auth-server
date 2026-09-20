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
        return DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var verifiedAt) &&
               verifiedAt <= now && now - verifiedAt <= maximumAge;
    }
}
