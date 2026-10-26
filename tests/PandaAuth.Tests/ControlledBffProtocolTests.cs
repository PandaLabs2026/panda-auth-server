using System.Net;
using PandaAuth.ReadinessHarness;
using Xunit;
namespace PandaAuth.Tests;
public sealed class ControlledBffProtocolTests
{
    [Fact]
    public async Task MissingAdmissionCannotStartAProtocolProbe()
        => Assert.Equal(2,await ControlledBffProtocol.Dispatch("{}"));
    [Fact]
    public async Task OriginalHostStillCannotUseTheSyntheticLoginEntry()
    {
        using var browser=new HttpClient(){BaseAddress=new Uri("https://auth.appliket.com/")};
        var settings=new LoadRequest{RunId=new string('a',32),BaseUri=browser.BaseAddress.AbsoluteUri,RootCertificateFile="/fixture/root.pem",
            Password="private",ClientSecret="private",Workload="cookie",Concurrency=1,DurationSeconds=1,RecoveryScenario=true,
            RecoveryTotpKey=Convert.ToBase64String(new byte[32])};
        await Assert.ThrowsAsync<InvalidOperationException>(()=>BffLogin.VerifyAsync(settings,browser));
    }
}
