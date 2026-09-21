using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public enum MfaFactorType { Totp, WebAuthn }

public sealed class MfaPolicyException(string message) : InvalidOperationException(message);

public sealed record MfaStatus(bool HasActiveFactor, bool RequiresReconfiguration, int RecoveryCodeCount);

public sealed class MfaService(
    PandaAuthDbContext db,
    UserService users,
    TotpFactorService totpFactors,
    LoginSessionService sessions,
    TimeProvider clock)
{
    private readonly LoginSessionService _sessions = sessions;
    private const int RecoveryCodeCount = 10;

    public async Task<TotpEnrollment> BeginEnrollmentAsync(
        string userId, ClaimsPrincipal principal, MfaFactorType factor, CancellationToken cancellationToken)
    {
        await RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);
        if (factor != MfaFactorType.Totp)
            throw new MfaPolicyException("WebAuthn enrollment must use its ceremony service.");
        return await totpFactors.BeginEnrollmentAsync(userId, cancellationToken);
    }

    public async Task<bool> ConfirmEnrollmentAsync(
        string userId, Guid factorId, string code, CancellationToken cancellationToken)
        => await totpFactors.ConfirmAsync(userId, factorId, code, cancellationToken);

    public Task<bool> VerifyAsync(string userId, string code, CancellationToken cancellationToken)
        => totpFactors.VerifyAsync(userId, code, cancellationToken);

    public async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(
        string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        await RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);
        var old = await db.MfaRecoveryCodes.Where(x => x.UserId == userId && x.ConsumedAt == null).ToListAsync(cancellationToken);
        db.MfaRecoveryCodes.RemoveRange(old);
        var codes = new List<string>(RecoveryCodeCount);
        for (var i = 0; i < RecoveryCodeCount; i++)
        {
            var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            var salt = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            db.MfaRecoveryCodes.Add(new MfaRecoveryCode
            {
                UserId = userId,
                CodeHash = HashRecoveryCode(salt, code),
                Salt = salt,
                CreatedAt = clock.GetUtcNow()
            });
            codes.Add(code);
        }
        await db.SaveChangesAsync(cancellationToken);
        return codes;
    }

    public async Task<bool> ConsumeRecoveryCodeAsync(string userId, string code, CancellationToken cancellationToken)
    {
        var candidates = await db.MfaRecoveryCodes
            .Where(x => x.UserId == userId && x.ConsumedAt == null)
            .ToListAsync(cancellationToken);
        foreach (var candidate in candidates)
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(candidate.CodeHash), Convert.FromHexString(HashRecoveryCode(candidate.Salt, code))))
                continue;
            var consumedAt = clock.GetUtcNow();
            if (db.Database.IsRelational())
            {
                var updated = await db.Database.ExecuteSqlInterpolatedAsync($"""
                    UPDATE panda_mfa_recovery_codes SET "ConsumedAt" = {consumedAt}
                    WHERE "Id" = {candidate.Id} AND "ConsumedAt" IS NULL
                    """, cancellationToken);
                db.ChangeTracker.Clear();
                return updated == 1;
            }
            candidate.ConsumedAt = consumedAt;
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        return false;
    }

    public async Task RevokeFactorAsync(string userId, Guid factorId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        await RequireRecentAuthenticationAsync(userId, principal, cancellationToken);
        var totp = await db.TotpFactors.SingleOrDefaultAsync(x => x.Id == factorId && x.UserId == userId && x.RevokedAt == null, cancellationToken);
        var activeTotp = await db.TotpFactors.CountAsync(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null, cancellationToken);
        var activeWebAuthn = await db.WebAuthnCredentials.CountAsync(x => x.UserId == userId && x.RevokedAt == null, cancellationToken);
        if (totp is not null)
        {
            if (activeTotp + activeWebAuthn <= 1)
                throw new MfaPolicyException("Cannot remove the last active factor.");
            totp.RevokedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(cancellationToken);
            return;
        }
        throw new MfaPolicyException("Factor not found.");
    }

    public async Task<MfaStatus> GetStatusAsync(string userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId) ?? throw new MfaPolicyException("User not found.");
        var totp = await db.TotpFactors.AnyAsync(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null, cancellationToken);
        var passkey = await db.WebAuthnCredentials.AnyAsync(x => x.UserId == userId && x.RevokedAt == null, cancellationToken);
        var recovery = await db.MfaRecoveryCodes.CountAsync(x => x.UserId == userId && x.ConsumedAt == null, cancellationToken);
        return new MfaStatus(totp || passkey, user.TwoFactorEnabled && !totp && !passkey, recovery);
    }

    private async Task RequireEnrollmentPolicyAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId) ?? throw new MfaPolicyException("User not found.");
        if (!user.EmailConfirmed) throw new MfaPolicyException("Email confirmation is required.");
        await RequireRecentAuthenticationAsync(userId, principal, cancellationToken);
    }

    private async Task RequireRecentAuthenticationAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        if (principal.FindFirstValue(ClaimTypes.NameIdentifier) != userId ||
            !RecentMfaRequirement.HasValidMfa(principal, clock.GetUtcNow(), TimeSpan.FromMinutes(5)))
            throw new MfaPolicyException("Recent MFA authentication is required.");
        await Task.CompletedTask;
    }

    private static string HashRecoveryCode(string salt, string code)
        => Convert.ToHexString(Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(salt + ":" + code),
            Encoding.UTF8.GetBytes(salt),
            100_000,
            HashAlgorithmName.SHA256,
            32)).ToLowerInvariant();
}
