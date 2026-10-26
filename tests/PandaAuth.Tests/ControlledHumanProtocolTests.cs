using PandaAuth.ReadinessHarness;
using Xunit;
namespace PandaAuth.Tests;
public sealed class ControlledHumanProtocolTests
{
    [Fact]
    public void CasesCannotSelectAnOriginalAccountOrArbitraryFile()
    {
        Assert.Equal(0,ControlledHumanProtocol.CaseIndex("valid"));Assert.Equal(1,ControlledHumanProtocol.CaseIndex("revoked"));
        foreach(var value in new[]{"original-admin","../valid","legacy",""})
            Assert.ThrowsAny<Exception>(()=>ControlledHumanProtocol.CaseIndex(value));
    }
    [Theory]
    [InlineData("--controlled-human-create-stdin")][InlineData("--controlled-human-verify-stdin")]
    public async Task MissingAdmissionCannotReachAnyHumanSession(string command)
        => Assert.Equal(2,await ControlledHumanProtocol.Dispatch(command,"{}"));
}
