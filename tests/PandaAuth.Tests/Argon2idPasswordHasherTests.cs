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
        var hash = _hasher.Hash("Sup3r$ecret-Password");
        var result = _hasher.Verify(hash, "Sup3r$ecret-Password");

        Assert.Equal(PasswordVerificationOutcome.Success, result);
    }

    [Fact]
    public void Verify_WrongPassword_Fails()
    {
        var hash = _hasher.Hash("Sup3r$ecret-Password");

        Assert.Equal(PasswordVerificationOutcome.Failed,
            _hasher.Verify(hash, "wrong-password"));
    }

    [Fact]
    public void Verify_MalformedHash_Fails()
    {
        var result = _hasher.Verify("not-a-phc-string", "whatever");

        Assert.Equal(PasswordVerificationOutcome.Failed, result);
    }

    [Fact]
    public void Hash_SamePassword_Twice_ProducesDifferentSalts()
    {
        var first = _hasher.Hash("same-password");
        var second = _hasher.Hash("same-password");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Hash_UsesPhcArgon2idFormat()
    {
        var hash = _hasher.Hash("whatever");

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

        var result = _hasher.Verify(legacyHash, "legacy-password");

        Assert.Equal(PasswordVerificationOutcome.SuccessRehashNeeded, result);
    }
}
