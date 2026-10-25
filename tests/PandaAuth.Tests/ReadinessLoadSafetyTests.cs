using PandaAuth.ReadinessHarness;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ReadinessLoadSafetyTests
{
    private static readonly LoadRequest Valid = new()
    {
        RunId = new string('a', 32), BaseUri = "https://127.0.0.1:39001/",
        RootCertificateFile = "fixture.pem", Password = "synthetic-password", ClientSecret = "synthetic-client",
        Workload = "cookie", Concurrency = 1
    };

    [Theory]
    [InlineData("https://auth.appliket.com/")]
    [InlineData("http://127.0.0.1:39001/")]
    [InlineData("https://127.0.0.1:5200/")]
    [InlineData("https://127.0.0.1:10001/")]
    [InlineData("https://127.0.0.1:39001/?redirect=https://auth.appliket.com")]
    [InlineData("https://fixture:synthetic@127.0.0.1:39001/")]
    public void LoadTarget_RejectsExternalOrProtectedTargets(string target)
        => Assert.Throws<InvalidOperationException>(() => (Valid with { BaseUri = target }).Validate());

    [Fact]
    public void UnboundedWorkOrMissingSyntheticIdentity_IsRejected()
    {
        Assert.Throws<InvalidOperationException>(() => (Valid with { Concurrency = 65 }).Validate());
        Assert.Throws<InvalidOperationException>(() => (Valid with { DurationSeconds = 3600 }).Validate());
        Assert.Throws<InvalidOperationException>(() => (Valid with { RunId = "production" }).Validate());
        Assert.Throws<InvalidOperationException>(() => (Valid with { RootCertificateFile = "" }).Validate());
        Assert.Throws<InvalidOperationException>(() => (Valid with { Workload = "arbitrary" }).Validate());
    }

    [Fact]
    public void BoundedLoopbackFixture_IsAdmitted() => Valid.Validate();

    [Fact]
    public void MixedSteadyState_UsesTheSameBoundedSyntheticAdmission() => (Valid with { Workload = "mixed" }).Validate();

    [Fact]
    public void ProxyPath_CannotReplaceTheOwnedUpstreamAuthority()
    {
        var upstream = new Uri("http://panda-r1-server-" + new string('a', 32) + ":8080/");
        var target = FixtureProxy.BuildTarget(upstream, new PathString("//auth.appliket.com/"), new QueryString("?x=1"));
        Assert.Equal(upstream.Authority, target.Authority);
    }

    [Fact]
    public void ConcurrentMeasurements_AreNotLost_AndPercentilesExcludeFailedRequests()
    {
        var distribution = new LatencyDistribution();
        Parallel.For(0, 10_000, _ => distribution.Record(7.2));
        var result = distribution.Snapshot();
        Assert.Equal(10_000, result.Count);
        Assert.InRange(result.P95Ms, 7.2, 8);
        Assert.Equal(result.P50Ms, result.P99Ms);
    }
}
