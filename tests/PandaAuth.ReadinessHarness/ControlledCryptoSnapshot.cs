using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using PandaAuth.Server.Infrastructure.Security.Mfa;

namespace PandaAuth.ReadinessHarness;

public sealed record ControlledCryptoState(Dictionary<string,string> Keys, Dictionary<string,string> Factors);

/// <summary>Fixed legacy-compatible SQL, read-only transaction, existing isolated namespace only.</summary>
public static class ControlledCryptoSnapshot
{
    public static string Hash(params string[] fields) => Convert.ToHexStringLower(
        SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(fields)));
    public static string Fingerprint(string database, string oid) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes("127.0.0.1\0"+"55432\0"+database+"\0"+oid)));
    private static void Require(bool value)
    { if (!value) throw new CryptographicException("controlled_crypto_failed"); }

    public static async Task<ControlledCryptoState> Read(ControlledCryptoInput input)
    {
        var root=ControlledTransport.Guard(input.Spec);
        Require(File.ReadAllText(Path.Combine(root,"transport.json")) == ControlledTransport.Canonical(input.Spec));
        var settings=ControlledCryptography.Connection(input.ConnectionString);
        var key=Convert.FromBase64String(input.TotpKey);
        Require(key.Length==32 && input.TotpKeyVersion.Length is >=1 and <=32);
        try
        {
            var protector=new TotpSecretProtector(key,input.TotpKeyVersion);
            await using var connection=new NpgsqlConnection(settings.ConnectionString);
            await connection.OpenAsync();
            await using var transaction=await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
            await using(var command=new NpgsqlCommand("SET TRANSACTION READ ONLY",connection,transaction))
                await command.ExecuteNonQueryAsync();
            await using(var command=new NpgsqlCommand("SELECT oid::text FROM pg_database WHERE datname=current_database()",connection,transaction))
                Require(Fingerprint(settings.Database!, (string)(await command.ExecuteScalarAsync() ?? "")) == input.RestoredDatabaseFingerprint);
            var keys=new Dictionary<string,string>(StringComparer.Ordinal);
            // Historical columns only: valid both before and after the online key-ring migration.
            await using(var command=new NpgsqlCommand("SELECT \"KeyId\",\"Use\",\"Algorithm\",\"PrivateKey\",\"NotBefore\",\"NotAfter\" FROM signing_keys ORDER BY \"KeyId\" LIMIT 513",connection,transaction))
            await using(var reader=await command.ExecuteReaderAsync())
            {
                while(await reader.ReadAsync())
                {
                    Require(keys.Count<512);
                    var material=reader.GetFieldValue<byte[]>(3);
                    try
                    {
                        var materialHash=ControlledCryptography.InspectRsa(reader.GetString(1),reader.GetString(2),material);
                        keys.Add(Hash(reader.GetString(0)),Hash(reader.GetString(0),reader.GetString(1),reader.GetString(2),materialHash,
                            reader.GetDateTime(4).ToString("O",CultureInfo.InvariantCulture),reader.GetDateTime(5).ToString("O",CultureInfo.InvariantCulture)));
                    }
                    finally { CryptographicOperations.ZeroMemory(material); }
                }
            }
            var factors=new Dictionary<string,string>(StringComparer.Ordinal);
            await using(var command=new NpgsqlCommand("SELECT \"Id\",\"UserId\",\"KeyVersion\",\"Nonce\",\"Ciphertext\",\"Tag\" FROM panda_totp_factors WHERE \"RevokedAt\" IS NULL ORDER BY \"Id\" LIMIT 16385",connection,transaction))
            await using(var reader=await command.ExecuteReaderAsync())
            {
                while(await reader.ReadAsync())
                {
                    Require(factors.Count<16384);
                    var factor=reader.GetGuid(0);var user=reader.GetString(1);
                    var value=new ProtectedTotpSecret(reader.GetString(2),reader.GetFieldValue<byte[]>(3),reader.GetFieldValue<byte[]>(4),reader.GetFieldValue<byte[]>(5));
                    Require(value.Nonce.Length==12 && value.Tag.Length==16 && value.Ciphertext.Length is >=20 and <=1024);
                    var plaintextHash=ControlledCryptography.InspectTotp(protector,user,factor,value);
                    factors.Add(Hash(factor.ToString("D")),Hash(user,factor.ToString("D"),value.KeyVersion,
                        Convert.ToBase64String(value.Nonce),Convert.ToBase64String(value.Ciphertext),Convert.ToBase64String(value.Tag),plaintextHash));
                }
            }
            // No tracked entities, key-store refresh, TOTP service calls, or writes, including empty-factor databases.
            await transaction.RollbackAsync();
            return new(keys,factors);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
