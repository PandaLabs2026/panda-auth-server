using Microsoft.AspNetCore.Identity;
using Xunit;
using System.Text;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Tests;

public class Argon2idPasswordHasherTests
{
    private readonly Argon2idPasswordHasher _hasher = new();

    [Fact]
    public void Hash_ThenVerify_CorrectPassword_Succeeds()
    {
        var hash = _hasher.HashPassword(new PandaAuthUser(), "Sup3r$ecret-Password");
        var result = _hasher.VerifyHashedPassword(new PandaAuthUser(), hash, "Sup3r$ecret-Password");

        Assert.Equal(PasswordVerificationResult.Success, result);
    }

    [Fact]
    public void Verify_WrongPassword_Fails()
    {
        var hash = _hasher.HashPassword(new PandaAuthUser(), "Sup3r$ecret-Password");

        Assert.Equal(PasswordVerificationResult.Failed,
            _hasher.VerifyHashedPassword(new PandaAuthUser(), hash, "wrong-password"));
    }

    [Fact]
    public void Verify_MalformedHash_Fails()
    {
        var result = _hasher.VerifyHashedPassword(new PandaAuthUser(), "not-a-phc-string", "whatever");

        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    [Fact]
    public void Hash_SamePassword_Twice_ProducesDifferentSalts()
    {
        var first = _hasher.HashPassword(new PandaAuthUser(), "same-password");
        var second = _hasher.HashPassword(new PandaAuthUser(), "same-password");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Hash_UsesPhcArgon2idFormat()
    {
        var hash = _hasher.HashPassword(new PandaAuthUser(), "whatever");

        Assert.StartsWith(
            $"$argon2id$v=19$m={Argon2idPasswordHasher.MemorySizeKib},t={Argon2idPasswordHasher.Iterations},p={Argon2idPasswordHasher.Parallelism}$",
            hash, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_WeakerParameters_RequestsRehash()
    {
        // 模拟历史低参数哈希：m=8192,t=1 验证成功但要求重哈希。
        var salt = Encoding.UTF8.GetBytes("0123456789abcdef");
        var legacyHash = Argon2idPasswordHasher.Format(
            salt, Argon2idPasswordHasher.Compute("legacy-password", salt, 8192, 1, 1), 8192, 1, 1);

        var result = _hasher.VerifyHashedPassword(new PandaAuthUser(), legacyHash, "legacy-password");

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, result);
    }
}
