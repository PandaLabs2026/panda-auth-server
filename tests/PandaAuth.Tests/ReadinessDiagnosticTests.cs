using System.Text.Json;
using System.Net;
using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ReadinessDiagnosticTests
{
    [Fact]
    public void RedirectDiagnosticsOnlyExposeBoundedCategories()
    {
        var exception = new SnapshotProtocolException(HttpStatusCode.Redirect, HttpStatusCode.Unauthorized,
            HttpStatusCode.BadRequest, false, "invalid_grant", new Uri("https://localhost:39001/"),
            new Uri("https://synthetic-sensitive.example/unknown?token=synthetic-sensitive-token"));
        var json = JsonSerializer.Serialize(HarnessProgram.DescribeFailure(exception));
        Assert.DoesNotContain("synthetic-sensitive", json);
        Assert.Contains("other", json);
        Assert.False(exception.RedirectOwnerMatches);
    }

    [Fact]
    public void FailureDiagnosticsNeverSerializeExceptionMessagesOrProviderData()
    {
        var exception = new InvalidOperationException("synthetic-sensitive-token-do-not-emit");
        exception.Data["ConnectionStrings:Default"] = "synthetic-sensitive-provider-do-not-emit";
        var json = JsonSerializer.Serialize(HarnessProgram.DescribeFailure(exception));
        Assert.DoesNotContain("synthetic-sensitive", json);
        Assert.Contains("InvalidOperationException", json);
    }
}
