using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Globalization;

namespace PandaAuth.ReadinessHarness;

public static class FixtureRecoveryState
{
    public static async Task PopulateAsync(PandaAuthDbContext db, UserService users, LoginSessionService sessions,
        LoadRequest settings, PandaUser administrator)
    {
        settings.Validate();
        if (!settings.RecoveryScenario || administrator.UserName != settings.AdminUserName ||
            !await db.TotpFactors.AnyAsync(row => row.UserId == administrator.Id && row.ConfirmedAt != null && row.RevokedAt == null))
            throw new InvalidOperationException("recovery_fixture_state_admission_invalid");
        if (await db.MfaRecoveryCodes.AnyAsync(row => row.UserId == administrator.Id))
            throw new InvalidOperationException("recovery_fixture_state_already_exists");
        var clock = TimeProvider.System;
        var mfa = new MfaService(db, users, new TotpFactorService(db,
            new TotpSecretProtector(Convert.FromBase64String(settings.RecoveryTotpKey), "v1"), clock), sessions, clock);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, administrator.Id),
            new Claim(MfaClaimTypes.Method, MfaClaimTypes.Totp),
            new Claim(MfaClaimTypes.VerifiedAt, clock.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
        ], LoginSessionService.Scheme));
        // Synthetic seed data uses the production generator/consumer; plaintext
        // codes never leave this method or enter the fixture report/archive.
        var codes = await mfa.GenerateRecoveryCodesAsync(administrator.Id, principal, CancellationToken.None);
        if (codes.Count != 10 || !await mfa.ConsumeRecoveryCodeAsync(administrator.Id, codes[0], CancellationToken.None) ||
            await mfa.ConsumeRecoveryCodeAsync(administrator.Id, codes[0], CancellationToken.None))
            throw new InvalidOperationException("recovery_fixture_code_state_invalid");
        db.MfaRecoveryEvents.Add(new MfaRecoveryEvent { ActorUserId = administrator.Id, TargetUserId = administrator.Id,
            Reason = "readiness_fixture", AuthenticationMethod = MfaClaimTypes.Totp, RequestId = settings.RunId });
        db.AdminAuditLogs.Add(new AdminAuditLog { ActorUserId = administrator.Id, ActorUserName = administrator.UserName,
            Action = "readiness_fixture.seed", TargetType = "user", TargetId = administrator.Id });
        await db.SaveChangesAsync();
    }
}
