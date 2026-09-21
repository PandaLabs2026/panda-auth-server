using OpenIddict.Server;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class RefreshTokenPolicyTests
{
    [Fact]
    public void UsesRollingTokensWithShortConcurrentRequestLeeway()
    {
        var options = new OpenIddictServerOptions();

        RefreshTokenPolicy.Configure(options);

        Assert.False(options.DisableRollingRefreshTokens);
        Assert.Equal(TimeSpan.FromSeconds(5), options.RefreshTokenReuseLeeway);
    }
}
