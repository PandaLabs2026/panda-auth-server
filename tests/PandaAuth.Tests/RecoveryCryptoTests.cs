using System.Security.Cryptography;
using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class RecoveryCryptoTests : IDisposable
{
    private readonly string run = Guid.NewGuid().ToString("N");
    private readonly string root;
    private readonly byte[] key = RandomNumberGenerator.GetBytes(32);

    public RecoveryCryptoTests()
    {
        root = Path.Combine(Path.GetTempPath(), "panda-r1-recovery-" + run);
        Directory.CreateDirectory(root);
    }

    [Fact]
    public void CopyOfAllThreeKeyringsAndTotpKey_IsUsableWithoutKeyGeneration()
    {
        RecoveryCrypto.Create(root, run, key);
        var before = Directory.GetFiles(root, "*.xml", SearchOption.AllDirectories).Order().ToArray();
        Assert.Equal(3, before.Length);
        Assert.True(RecoveryCrypto.Verify(root, run, key));
        Assert.Equal(before, Directory.GetFiles(root, "*.xml", SearchOption.AllDirectories).Order().ToArray());
    }

    [Fact]
    public void ExistingServiceKeyringsCanProtectACanaryWithoutCreatingOrChangingKeys()
    {
        RecoveryCrypto.Create(root, run, key);
        File.Delete(Path.Combine(root, "crypto-canary.json"));
        var before = Directory.GetFiles(root, "*.xml", SearchOption.AllDirectories).ToDictionary(path => path,
            path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
        RecoveryCrypto.Create(root, run, key, useExistingKeyrings: true);
        Assert.True(RecoveryCrypto.Verify(root, run, key));
        Assert.Equal(before.OrderBy(pair => pair.Key), Directory.GetFiles(root, "*.xml", SearchOption.AllDirectories)
            .ToDictionary(path => path, path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).OrderBy(pair => pair.Key));
    }

    [Fact]
    public void ExistingKeyringModeCannotReplaceAMissingServiceStore()
    {
        foreach (var component in new[] { "server", "admin", "me" }) Directory.CreateDirectory(Path.Combine(root, component));
        Assert.ThrowsAny<Exception>(() => RecoveryCrypto.Create(root, run, key, useExistingKeyrings: true));
        Assert.Empty(Directory.GetFiles(root, "*.xml", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData("server")]
    [InlineData("admin")]
    [InlineData("me")]
    public void MissingKeyring_IsRejectedAndNotReplaced(string component)
    {
        RecoveryCrypto.Create(root, run, key);
        foreach (var file in Directory.GetFiles(Path.Combine(root, component))) File.Delete(file);
        Assert.ThrowsAny<Exception>(() => RecoveryCrypto.Verify(root, run, key));
        Assert.Empty(Directory.GetFiles(Path.Combine(root, component)));
    }

    [Fact]
    public void WrongTotpKeyOrCorruptedCanary_IsRejected()
    {
        RecoveryCrypto.Create(root, run, key);
        Assert.ThrowsAny<Exception>(() => RecoveryCrypto.Verify(root, run, RandomNumberGenerator.GetBytes(32)));
        File.WriteAllText(Path.Combine(root, "crypto-canary.json"), "{}");
        Assert.ThrowsAny<Exception>(() => RecoveryCrypto.Verify(root, run, key));
    }

    [Fact]
    public void UnownedDirectory_IsRejectedBeforeWriting()
    {
        Assert.ThrowsAny<Exception>(() => RecoveryCrypto.Create(Path.GetTempPath(), run, key));
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}
