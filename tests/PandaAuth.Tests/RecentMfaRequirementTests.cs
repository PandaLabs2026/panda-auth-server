using System.Security.Claims;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 8 小时窗的方法口径（Passkey 退役后，AUTH-DELIVERY-002）：TOTP 与恢复码满足普通写操作；
/// 存量令牌上的历史 webauthn amr 在窗口内仍被承认（不再新产生），高风险操作已改走操作授权。
/// </summary>
public class RecentMfaRequirementTests
{
    [Fact]
    public void TotpFallback_SatisfiesValidMfaWindow()
    {
        var now = DateTimeOffset.Parse("2026-09-20T12:00:00Z");
        var principal = Principal("totp", now);

        Assert.True(RecentMfaRequirement.HasValidMfa(principal, now, TimeSpan.FromHours(8)));
        Assert.False(RecentMfaRequirement.HasValidMfa(principal, now.AddHours(9), TimeSpan.FromHours(8)));
    }

    [Fact]
    public void LegacyWebAuthnAmr_FromPreRetirementTokens_IsStillHonoredWithinWindow()
    {
        var now = DateTimeOffset.Parse("2026-09-20T12:00:00Z");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(MfaClaimTypes.Method, MfaClaimTypes.WebAuthn),
            new Claim(MfaClaimTypes.VerifiedAt, now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
        ], "test"));

        Assert.True(RecentMfaRequirement.HasValidMfa(principal, now, TimeSpan.FromHours(8)));
        Assert.True(RecentMfaRequirement.HasValidMfa(principal, now, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void RecoveryCode_IsAnMfaMethod()
    {
        var now = DateTimeOffset.Parse("2026-09-20T12:00:00Z");
        var principal = Principal(MfaClaimTypes.RecoveryCode, now);

        Assert.True(RecentMfaRequirement.HasValidMfa(principal, now, TimeSpan.FromMinutes(5)));
        Assert.False(RecentMfaRequirement.HasValidMfa(principal, now.AddMinutes(6), TimeSpan.FromMinutes(5)));
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
