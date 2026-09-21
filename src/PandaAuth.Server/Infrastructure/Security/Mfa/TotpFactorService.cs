using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public sealed record TotpEnrollment(Guid FactorId, string Secret, string ProvisioningUri);

/// <summary>Creates and confirms the encrypted TOTP fallback factor after a Passkey already exists.</summary>
public sealed class TotpFactorService(PandaAuthDbContext db, TotpSecretProtector protector, TimeProvider clock)
{
    public async Task<TotpEnrollment> BeginEnrollmentAsync(
        string userId, CancellationToken cancellationToken, bool requirePasskey = true)
    {
        var hasPasskey = await db.WebAuthnCredentials.AnyAsync(item => item.UserId == userId && item.RevokedAt == null, cancellationToken);
        if (requirePasskey && !hasPasskey) throw new InvalidOperationException("启用 TOTP 前必须已有有效 Passkey。");
        var pending = await db.TotpFactors
            .Where(item => item.UserId == userId && item.RevokedAt == null && item.ConfirmedAt == null)
            .ToListAsync(cancellationToken);
        foreach (var pendingFactor in pending)
            pendingFactor.RevokedAt = clock.GetUtcNow();
        if (await db.TotpFactors.AnyAsync(item => item.UserId == userId && item.RevokedAt == null && item.ConfirmedAt != null, cancellationToken))
            throw new InvalidOperationException("此账号已有未撤销的 TOTP 因子。");

        var factor = new MfaTotpFactor { Id = Guid.NewGuid(), UserId = userId, CreatedAt = clock.GetUtcNow() };
        var secret = RandomNumberGenerator.GetBytes(20);
        var protectedSecret = protector.Protect(userId, factor.Id, secret);
        factor.KeyVersion = protectedSecret.KeyVersion;
        factor.Nonce = protectedSecret.Nonce;
        factor.Ciphertext = protectedSecret.Ciphertext;
        factor.Tag = protectedSecret.Tag;
        db.TotpFactors.Add(factor);
        await db.SaveChangesAsync(cancellationToken);

        var encoded = Base32(secret);
        return new TotpEnrollment(factor.Id, encoded,
            $"otpauth://totp/{Uri.EscapeDataString("PandaAuth")}:" + Uri.EscapeDataString(userId) +
            $"?secret={encoded}&issuer=PandaAuth&algorithm=SHA1&digits=6&period=30");
    }

    public async Task<bool> ConfirmAsync(string userId, Guid factorId, string code, CancellationToken cancellationToken)
    {
        var factor = await db.TotpFactors.SingleOrDefaultAsync(item => item.Id == factorId && item.UserId == userId && item.RevokedAt == null, cancellationToken);
        if (factor is null) return false;
        var secret = protector.Unprotect(userId, factor.Id, new ProtectedTotpSecret(factor.KeyVersion, factor.Nonce, factor.Ciphertext, factor.Tag));
        if (!TotpVerifier.TryVerify(secret, code, clock.GetUtcNow(), factor.LastAcceptedTimeStep, out var step)) return false;
        factor.LastAcceptedTimeStep = step;
        factor.ConfirmedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> VerifyAsync(string userId, string code, CancellationToken cancellationToken)
    {
        var factor = await db.TotpFactors.SingleOrDefaultAsync(item => item.UserId == userId && item.RevokedAt == null && item.ConfirmedAt != null, cancellationToken);
        if (factor is null) return false;
        var secret = protector.Unprotect(userId, factor.Id, new ProtectedTotpSecret(factor.KeyVersion, factor.Nonce, factor.Ciphertext, factor.Tag));
        if (!TotpVerifier.TryVerify(secret, code, clock.GetUtcNow(), factor.LastAcceptedTimeStep, out var step)) return false;
        factor.LastAcceptedTimeStep = step;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static string Base32(byte[] bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new System.Text.StringBuilder((bytes.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;
        foreach (var value in bytes)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5) { output.Append(alphabet[(buffer >> (bits -= 5)) & 31]); }
        }
        if (bits > 0) output.Append(alphabet[(buffer << (5 - bits)) & 31]);
        return output.ToString();
    }
}
