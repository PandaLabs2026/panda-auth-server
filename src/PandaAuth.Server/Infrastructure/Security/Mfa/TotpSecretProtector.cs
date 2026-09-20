using System.Security.Cryptography;
using System.Text;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public sealed record ProtectedTotpSecret(string KeyVersion, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

public sealed class TotpSecretProtector
{
    private readonly byte[] key;
    private readonly string keyVersion;

    public TotpSecretProtector(byte[] key, string keyVersion)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 32);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyVersion);
        this.key = [.. key];
        this.keyVersion = keyVersion;
    }

    public ProtectedTotpSecret Protect(string userId, Guid factorId, byte[] secret)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[secret.Length];
        var tag = new byte[16];
        using var cipher = new AesGcm(key, tag.Length);
        cipher.Encrypt(nonce, secret, ciphertext, tag, AssociatedData(userId, factorId, keyVersion));
        return new ProtectedTotpSecret(keyVersion, nonce, ciphertext, tag);
    }

    public byte[] Unprotect(string userId, Guid factorId, ProtectedTotpSecret protectedSecret)
    {
        if (!string.Equals(keyVersion, protectedSecret.KeyVersion, StringComparison.Ordinal))
        {
            throw new CryptographicException("TOTP 密钥版本不可用。");
        }

        var plaintext = new byte[protectedSecret.Ciphertext.Length];
        using var cipher = new AesGcm(key, protectedSecret.Tag.Length);
        cipher.Decrypt(protectedSecret.Nonce, protectedSecret.Ciphertext, protectedSecret.Tag, plaintext,
            AssociatedData(userId, factorId, keyVersion));
        return plaintext;
    }

    private static byte[] AssociatedData(string userId, Guid factorId, string keyVersion)
        => Encoding.UTF8.GetBytes($"{userId}:{factorId:D}:{keyVersion}");
}
