using PandaAuth.ReadinessHarness;
using Xunit;
using System.Security.Cryptography;

namespace PandaAuth.Tests;

public sealed class ProtocolSnapshotSafetyTests
{
    private static readonly LoadRequest Valid = new()
    {
        RunId = new string('b', 32), BaseUri = "https://localhost:39001/", RootCertificateFile = "fixture.pem",
        Password = "synthetic-only", ClientSecret = "synthetic-only", Workload = "cookie", Concurrency = 1,
        SnapshotFile = Path.Combine(Path.GetTempPath(), "panda-r1-session-" + new string('b', 32) + "-0.json")
    };

    [Fact]
    public void SnapshotFileMustBeNonceBoundAndInsideTheTaskTemporaryBoundary()
    {
        ProtocolSnapshot.ValidateFile(Valid);
        Assert.Throws<InvalidOperationException>(() => ProtocolSnapshot.ValidateFile(Valid with { SnapshotFile = "" }));
        Assert.Throws<InvalidOperationException>(() => ProtocolSnapshot.ValidateFile(Valid with { SnapshotFile = Path.Combine(Path.GetTempPath(), "other.json") }));
        Assert.Throws<InvalidOperationException>(() => ProtocolSnapshot.ValidateFile(Valid with { SnapshotUserIndex = 2 }));
        Assert.Throws<InvalidOperationException>(() => ProtocolSnapshot.ValidateFile(Valid with
        {
            SnapshotFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.GetFileName(Valid.SnapshotFile))
        }));
    }

    [Fact]
    public async Task DamagedSnapshotCannotMasqueradeAsARevokedTicket_OrReachTheNetwork()
    {
        var runId = Guid.NewGuid().ToString("N");
        var file = Path.Combine(Path.GetTempPath(), "panda-r1-session-" + runId + "-0.json");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using (var output = new FileStream(file, options)) await output.WriteAsync("{}"u8.ToArray());
        try
        {
            var request = Valid with { RunId = runId, SnapshotFile = file, SnapshotSha256 = new string('0', 64) };
            var damaged = await Assert.ThrowsAsync<InvalidOperationException>(() => ProtocolSnapshot.VerifyAsync(request, true));
            Assert.Contains("snapshot_hash_mismatch", damaged.Message);
            request = request with { SnapshotSha256 = Convert.ToHexStringLower(SHA256.HashData("{}"u8)) };
            var invalid = await Assert.ThrowsAsync<InvalidOperationException>(() => ProtocolSnapshot.VerifyAsync(request, true));
            Assert.Contains("snapshot_binding_invalid", invalid.Message);
        }
        finally { File.Delete(file); }
    }
}
