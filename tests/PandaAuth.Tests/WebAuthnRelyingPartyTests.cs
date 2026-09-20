using PandaAuth.Server.Configuration;
using Xunit;

namespace PandaAuth.Tests;

public class WebAuthnRelyingPartyTests
{
    [Fact]
    public void Create_BindsRpIdAndOriginToCanonicalHttpsIssuer()
    {
        var configuration = WebAuthnRelyingParty.Create("https://auth.pandalabs.cc/");

        Assert.Equal("auth.pandalabs.cc", configuration.ServerDomain);
        Assert.Contains("https://auth.pandalabs.cc", configuration.Origins);
    }

    [Fact]
    public void Create_RejectsNonHttpsIssuer()
    {
        Assert.Throws<InvalidOperationException>(() => WebAuthnRelyingParty.Create("http://auth.pandalabs.cc"));
    }

    [Fact]
    public void Create_AllowsLoopbackHttpForLocalBrowserDevelopment()
    {
        var configuration = WebAuthnRelyingParty.Create("http://localhost:9004/");

        Assert.Equal("localhost", configuration.ServerDomain);
    }
}
