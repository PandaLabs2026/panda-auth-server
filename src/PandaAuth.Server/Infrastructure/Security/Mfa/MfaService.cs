using System.Security.Claims;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public enum MfaFactorType { Totp, WebAuthn }

public sealed class MfaPolicyException(string message) : InvalidOperationException(message);

public sealed record MfaStatus(
    bool HasActiveFactor,
    bool RequiresReconfiguration,
    int RecoveryCodeCount,
    int ActivePasskeyCount);

public sealed record MfaFactorInfo(
    Guid Id,
    string Type,
    string? FriendlyName,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt);

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
        return await totpFactors.BeginEnrollmentAsync(userId, cancellationToken, requirePasskey: false);
    }

    public Task RequireEnrollmentAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
        => RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);

    public async Task<bool> ConfirmLegacyReconfigurationAsync(
        string userId, Guid factorId, string code, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId) ?? throw new MfaPolicyException("User not found.");
        if (!user.TwoFactorEnabled) throw new MfaPolicyException("MFA reconfiguration is not required.");
        if (!user.EmailConfirmed) throw new MfaPolicyException("Email confirmation is required.");
        if (!await totpFactors.ConfirmAsync(userId, factorId, code, cancellationToken)) return false;
        user.TwoFactorEnabled = false;
        var result = await users.UpdateAsync(user);
        if (!result.Succeeded) throw new MfaPolicyException("MFA reconfiguration could not be completed.");
        return true;
    }

    public async Task<bool> ConfirmEnrollmentAsync(
        string userId, ClaimsPrincipal principal, Guid factorId, string code, CancellationToken cancellationToken)
    {
        await RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);
        var confirmed = await totpFactors.ConfirmAsync(userId, factorId, code, cancellationToken);
        if (!confirmed) return false;
        var user = await users.FindByIdAsync(userId);
        if (user is not null && user.TwoFactorEnabled)
        {
            user.TwoFactorEnabled = false;
            await users.UpdateAsync(user);
        }
        return true;
    }

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
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            : null;
        var totp = await db.TotpFactors.SingleOrDefaultAsync(x => x.Id == factorId && x.UserId == userId && x.RevokedAt == null, cancellationToken);
        var activeTotp = await db.TotpFactors.CountAsync(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null, cancellationToken);
        var activeWebAuthn = await db.WebAuthnCredentials.CountAsync(x => x.UserId == userId && x.RevokedAt == null, cancellationToken);
        if (totp is not null)
        {
            if (activeTotp + activeWebAuthn <= 1)
                throw new MfaPolicyException("Cannot remove the last active factor.");
            totp.RevokedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(cancellationToken);
            if (transaction is not null) await transaction.CommitAsync(cancellationToken);
            return;
        }
        var passkey = await db.WebAuthnCredentials.SingleOrDefaultAsync(x => x.Id == factorId && x.UserId == userId && x.RevokedAt == null, cancellationToken);
        if (passkey is not null)
        {
            if (activeTotp + activeWebAuthn <= 1)
                throw new MfaPolicyException("Cannot remove the last active factor.");
            passkey.RevokedAt = clock.GetUtcNow();
            passkey.UpdatedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(cancellationToken);
            if (transaction is not null) await transaction.CommitAsync(cancellationToken);
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
        var activePasskeyCount = await db.WebAuthnCredentials.CountAsync(
            x => x.UserId == userId && x.RevokedAt == null, cancellationToken);
        return new MfaStatus(totp || passkey, user.TwoFactorEnabled && !totp && !passkey, recovery, activePasskeyCount);
    }

    /// <summary>自助管理的因子清单（撤销所需的 factorId 来源）。</summary>
    public async Task<IReadOnlyList<MfaFactorInfo>> ListFactorsAsync(string userId, CancellationToken cancellationToken)
    {
        var totp = await db.TotpFactors
            .Where(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null)
            .OrderBy(x => x.CreatedAt)
            .Select(x => new MfaFactorInfo(x.Id, "totp", null, x.CreatedAt, null))
            .ToListAsync(cancellationToken);
        var passkeys = await db.WebAuthnCredentials
            .Where(x => x.UserId == userId && x.RevokedAt == null)
            .OrderBy(x => x.CreatedAt)
            .Select(x => new MfaFactorInfo(x.Id, "passkey", x.FriendlyName, x.CreatedAt, x.LastUsedAt))
            .ToListAsync(cancellationToken);
        return [.. totp, .. passkeys];
    }

    private async Task RequireEnrollmentPolicyAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId) ?? throw new MfaPolicyException("User not found.");
        if (!user.EmailConfirmed) throw new MfaPolicyException("Email confirmation is required.");
        await RequireRecentAuthenticationAsync(userId, principal, cancellationToken);
    }

    /// <summary>近期认证窗口：所有自助 MFA 操作共用。</summary>
    private static readonly TimeSpan RecentAuthenticationWindow = TimeSpan.FromMinutes(5);

    private async Task RequireRecentAuthenticationAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        if (principal.FindFirstValue(ClaimTypes.NameIdentifier) != userId)
            throw new MfaPolicyException("Recent authentication is required.");
        var now = clock.GetUtcNow();
        if (RecentMfaRequirement.HasValidMfa(principal, now, RecentAuthenticationWindow))
            return;
        // 首因子解锁：amr 只能来自已完成的 MFA，账户没有任何活跃因子时不存在合法途径产生它，
        // 此时以 5 分钟内的密码登录（panda_authenticated_at）视为「近期重新认证」；
        // 已有因子后仍必须完成一次 MFA（防止仅凭密码注册第二因子绕过 step-up）。
        if (!await HasActiveFactorAsync(userId, cancellationToken) &&
            SessionSecurityService.HasRecentAuthentication(principal, now, RecentAuthenticationWindow))
            return;
        throw new MfaPolicyException("Recent MFA authentication is required.");
    }

    private async Task<bool> HasActiveFactorAsync(string userId, CancellationToken cancellationToken)
        => await db.TotpFactors.AnyAsync(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null, cancellationToken)
            || await db.WebAuthnCredentials.AnyAsync(x => x.UserId == userId && x.RevokedAt == null, cancellationToken);

    private static string HashRecoveryCode(string salt, string code)
        => Convert.ToHexString(Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(salt + ":" + code),
            Encoding.UTF8.GetBytes(salt),
            100_000,
            HashAlgorithmName.SHA256,
            32)).ToLowerInvariant();
}
