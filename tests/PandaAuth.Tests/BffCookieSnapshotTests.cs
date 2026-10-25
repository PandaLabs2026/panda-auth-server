using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class BffCookieSnapshotTests
{
    [Theory]
    [InlineData(200, 200)]
    [InlineData(401, 503)]
    [InlineData(403, 401)]
    public void LegacyCookieRejectionCannotAcceptAnAuthenticatedAdminOrAnUnavailableService(int admin, int me)
        => Assert.Throws<InvalidOperationException>(() => BffCookieSnapshot.RequireLegacyRejected(
            (System.Net.HttpStatusCode)admin, (System.Net.HttpStatusCode)me));

    private static LoadRequest Request(string runId, string file) => new()
    {
        RunId = runId, BaseUri = "https://localhost:39001/", RootCertificateFile = "fixture.pem",
        Password = "synthetic-only", ClientSecret = "synthetic-only", Workload = "cookie", Concurrency = 1,
        RecoveryScenario = true, RecoveryTotpKey = Convert.ToBase64String(new byte[32]), SnapshotFile = file
    };

    [Fact]
    public void BffFilesHaveAnIndependentNonceBoundNamespace()
    {
        var runId = Guid.NewGuid().ToString("N");
        var request = Request(runId, Path.Combine(Path.GetTempPath(), $"panda-r1-bff-{runId}-0.json"));
        ProtocolSnapshot.ValidateFile(request, bff: true);
        Assert.Throws<InvalidOperationException>(() => ProtocolSnapshot.ValidateFile(request));
    }

    [Fact]
    public async Task CorruptBffCookiesFailBeforeCertificatesOrNetworkAreAccessed()
    {
        var runId = Guid.NewGuid().ToString("N");
        var file = Path.Combine(Path.GetTempPath(), $"panda-r1-bff-{runId}-0.json");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using (var output = new FileStream(file, options)) await output.WriteAsync("{}"u8.ToArray());
        try
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => BffCookieSnapshot.VerifyAsync(
                Request(runId, file) with { SnapshotSha256 = new string('0', 64) }));
            Assert.Contains("snapshot_hash_mismatch", error.Message);
        }
        finally { File.Delete(file); }
    }
}
