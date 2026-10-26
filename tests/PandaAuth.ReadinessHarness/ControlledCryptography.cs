using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Npgsql;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security.Mfa;

namespace PandaAuth.ReadinessHarness;

public sealed record ControlledCryptoInput(ControlledTransportSpec Spec, string ConnectionString,
    string RestoredDatabaseFingerprint, string TotpKey, string TotpKeyVersion);

/// <summary>Read-only cryptographic primitives for restored original material; not a restore proof.</summary>
public static class ControlledCryptography
{
    private static void Require(bool value)
    {
        if (!value) throw new CryptographicException("controlled_crypto_failed");
    }

    private static IDataProtector Protector(string root, string component, string application)
    {
        var directory = Path.Combine(root, component);
        if (!Directory.Exists(directory) || new DirectoryInfo(directory).LinkTarget is not null)
            throw new RecoveryKeyringMissingException();
        var files = Directory.GetFiles(directory);
        Require(files.Any(path => Path.GetExtension(path) == ".xml") &&
            files.All(path => !File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint)));
        return DataProtectionProvider.Create(new DirectoryInfo(directory), builder =>
        {
            builder.SetApplicationName(application);
            builder.DisableAutomaticKeyGeneration();
        }).CreateProtector("PandaAuth.R1.ControlledRecoveryCanary");
    }

    private static string Value(ControlledTransportSpec spec, string component) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            ControlledTransport.Canonical(spec) + "\0" + component)));

    public static Dictionary<string,string> CaptureDp(string root, ControlledTransportSpec spec)
    {
        ControlledTransport.Validate(spec);
        return RecoveryCrypto.Applications.ToDictionary(pair => pair.Key,
            pair => Protector(root, pair.Key, pair.Value).Protect(Value(spec, pair.Key)));
    }

    public static void VerifyDp(string root, ControlledTransportSpec spec, IReadOnlyDictionary<string,string> canaries)
    {
        ControlledTransport.Validate(spec);
        Require(canaries.Keys.Order().SequenceEqual(RecoveryCrypto.Applications.Keys.Order()));
        foreach (var (component, application) in RecoveryCrypto.Applications)
            Require(Protector(root, component, application).Unprotect(canaries[component]) == Value(spec, component));
    }

    public static string InspectRsa(string use, string algorithm, byte[] material)
    {
        Require(material.Length is > 0 and <= 65536);
        using var privateKey = RSA.Create();
        privateKey.ImportPkcs8PrivateKey(material, out var consumed);
        Require(consumed == material.Length && privateKey.KeySize >= 2048);
        using var publicKey = RSA.Create();
        publicKey.ImportParameters(privateKey.ExportParameters(false));
        var challenge = RandomNumberGenerator.GetBytes(32);
        if (use == KeyUse.Signing && algorithm == "RS256")
            Require(publicKey.VerifyData(challenge, privateKey.SignData(challenge, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        else if (use == KeyUse.Encryption && algorithm == "RSA-OAEP-256")
            Require(CryptographicOperations.FixedTimeEquals(challenge,
                privateKey.Decrypt(publicKey.Encrypt(challenge, RSAEncryptionPadding.OaepSHA256), RSAEncryptionPadding.OaepSHA256)));
        else throw new CryptographicException("controlled_crypto_failed");
        return Convert.ToHexStringLower(SHA256.HashData(material));
    }

    public static string InspectTotp(TotpSecretProtector protector, string user, Guid factor, ProtectedTotpSecret value)
    {
        var secret = protector.Unprotect(user, factor, value);
        try
        {
            Require(secret.Length is >= 20 and <= 1024);
            var now = DateTimeOffset.UtcNow;
            Require(TotpVerifier.TryVerify(secret, BffSnapshot.TotpCode(secret, now), now, null, out _));
            return Convert.ToHexStringLower(SHA256.HashData(secret));
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    public static void RequireOriginals(IReadOnlyDictionary<string,string> original, IReadOnlyDictionary<string,string> current)
    {
        foreach (var (id, hash) in original)
            Require(current.TryGetValue(id, out var actual) && actual == hash);
    }

    public static NpgsqlConnectionStringBuilder Connection(string value)
    {
        var connection = new NpgsqlConnectionStringBuilder(value);
        Require(connection.Host == "127.0.0.1" && connection.Port == 55432 &&
            connection.Database is "panda_auth_fleet" or "panda_auth_t0000" &&
            connection.Username == connection.Database + "_runtime" && !string.IsNullOrEmpty(connection.Password));
        connection.Pooling = false;
        connection.Timeout = 10;
        connection.CommandTimeout = 30;
        return connection;
    }
}
