using System.Text.Json;
using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ReadinessDiagnosticTests
{
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
