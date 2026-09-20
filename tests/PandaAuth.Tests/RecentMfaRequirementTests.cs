using System.Security.Claims;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class RecentMfaRequirementTests
{
    [Fact]
    public void TotpFallback_DoesNotSatisfyRecentWebAuthnRequirement()
    {
        var now = DateTimeOffset.Parse("2026-09-20T12:00:00Z");
        var principal = Principal("totp", now);

        Assert.True(RecentMfaRequirement.HasValidMfa(principal, now, TimeSpan.FromHours(8)));
        Assert.False(RecentMfaRequirement.HasRecentWebAuthn(principal, now, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void UsedTotpTimeStep_CannotBeAcceptedAgain()
    {
        var secret = System.Text.Encoding.ASCII.GetBytes("12345678901234567890");
        var now = DateTimeOffset.FromUnixTimeSeconds(59);

        Assert.True(TotpVerifier.TryVerify(secret, "287082", now, null, out var acceptedStep));
        Assert.False(TotpVerifier.TryVerify(secret, "287082", now, acceptedStep, out _));
    }

    private static ClaimsPrincipal Principal(string method, DateTimeOffset verifiedAt)
        => new(new ClaimsIdentity(
        [
            new Claim(MfaClaimTypes.Method, method),
            new Claim(MfaClaimTypes.VerifiedAt, verifiedAt.ToString("O")),
        ], "test"));
}
