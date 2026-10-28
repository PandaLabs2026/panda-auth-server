using Xunit;
using PandaAuth.ReadinessHarness;
namespace PandaAuth.Tests;
public sealed class ControlledCryptoCommandTests
{
    [Theory]
    [InlineData("--controlled-crypto-baseline-stdin")]
    [InlineData("--controlled-crypto-verify-stdin")]
    public async Task MissingPrivateBoundaryCannotProduceSuccess(string command)
    {
        Assert.Equal(2,await ControlledCryptoCommand.Dispatch(command,"{}"));
    }
}
