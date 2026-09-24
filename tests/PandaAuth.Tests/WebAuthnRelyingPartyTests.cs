using PandaAuth.Server.Configuration;
using Xunit;

namespace PandaAuth.Tests;

public class WebAuthnRelyingPartyTests
{
    [Fact]
    public void Create_BindsRpIdAndOriginToCanonicalHttpsIssuer()
    {
        var configuration = WebAuthnRelyingParty.Create("https://auth.pandalabs.cn/");

        Assert.Equal("auth.pandalabs.cn", configuration.ServerDomain);
        Assert.Contains("https://auth.pandalabs.cn", configuration.Origins);
    }

    [Fact]
    public void Create_RejectsNonHttpsIssuer()
    {
        Assert.Throws<InvalidOperationException>(() => WebAuthnRelyingParty.Create("http://auth.pandalabs.cn"));
    }

    [Fact]
    public void Create_AllowsLoopbackHttpForLocalBrowserDevelopment()
    {
        var configuration = WebAuthnRelyingParty.Create("http://localhost:9004/");

        Assert.Equal("localhost", configuration.ServerDomain);
    }
}
