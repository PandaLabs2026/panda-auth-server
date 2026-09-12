using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using PandaAuth.Server.Domain;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// Argon2id 密码哈希（PHC 字符串格式：$argon2id$v=19$m=...,t=...,p=1$&lt;salt&gt;$&lt;hash&gt;）。
/// 参数采用 OWASP 基线：m=19456 KiB、t=2、p=1。
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher<PandaAuthUser>
{
    public const int MemorySizeKib = 19456;
    public const int Iterations = 2;
    public const int Parallelism = 1;

    private const int SaltSizeBytes = 16;
    private const int HashSizeBytes = 32;

    public string HashPassword(PandaAuthUser user, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var hash = Compute(password, salt, MemorySizeKib, Iterations, Parallelism);
        return Format(salt, hash, MemorySizeKib, Iterations, Parallelism);
    }

    public PasswordVerificationResult VerifyHashedPassword(PandaAuthUser user, string? hashedPassword, string providedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword) || !TryParse(hashedPassword, out var parsed))
        {
            return PasswordVerificationResult.Failed;
        }

        var expected = Compute(providedPassword, parsed.Salt, parsed.MemorySizeKib, parsed.Iterations, parsed.Parallelism);
        if (!CryptographicOperations.FixedTimeEquals(expected, parsed.Hash))
        {
            return PasswordVerificationResult.Failed;
        }

        // 参数低于当前基线时提示重哈希（下次登录成功后由 Identity 自动升级）。
        return parsed.MemorySizeKib < MemorySizeKib || parsed.Iterations < Iterations || parsed.Parallelism < Parallelism
            ? PasswordVerificationResult.SuccessRehashNeeded
            : PasswordVerificationResult.Success;
    }

    internal static string Format(byte[] salt, byte[] hash, int memorySizeKib, int iterations, int parallelism)
        => $"$argon2id$v=19$m={memorySizeKib},t={iterations},p={parallelism}${Base64(salt)}${Base64(hash)}";

    internal static byte[] Compute(string password, byte[] salt, int memorySizeKib, int iterations, int parallelism)
    {
        using var hasher = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memorySizeKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return hasher.GetBytes(HashSizeBytes);
    }

    private static bool TryParse(string encoded, out ParsedHash parsed)
    {
        parsed = default;

        // $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5 || parts[0] != "argon2id" || parts[1] != "v=19")
        {
            return false;
        }

        int memorySizeKib = 0, iterations = 0, parallelism = 0;
        foreach (var parameter in parts[2].Split(','))
        {
            var separatorIndex = parameter.IndexOf('=');
            if (separatorIndex <= 0 || !int.TryParse(parameter[(separatorIndex + 1)..], out var value))
            {
                return false;
            }

            switch (parameter[..separatorIndex])
            {
                case "m": memorySizeKib = value; break;
                case "t": iterations = value; break;
                case "p": parallelism = value; break;
                default: return false;
            }
        }

        if (memorySizeKib <= 0 || iterations <= 0 || parallelism <= 0 ||
            !TryFromBase64(parts[3], out var salt) || !TryFromBase64(parts[4], out var hash))
        {
            return false;
        }

        parsed = new ParsedHash(salt, hash, memorySizeKib, iterations, parallelism);
        return true;
    }

    private static string Base64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static bool TryFromBase64(string value, out byte[] bytes)
    {
        var padded = (value.Length % 4) switch
        {
            2 => value + "==",
            3 => value + "=",
            _ => value,
        };
        try
        {
            bytes = Convert.FromBase64String(padded);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    private readonly record struct ParsedHash(byte[] Salt, byte[] Hash, int MemorySizeKib, int Iterations, int Parallelism);
}
