using System.Text;
using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class BffSnapshotSafetyTests
{
    private static readonly Uri Owner = new("https://localhost:39001/");

    [Theory]
    [InlineData("https://auth.appliket.com/account/login")]
    [InlineData("//auth.appliket.com/account/login")]
    [InlineData("http://localhost:39001/account/login")]
    [InlineData("https://fixture@localhost:39001/account/login")]
    public void RedirectsCannotEscapeTheNonceBoundHttpsOwner(string location)
        => Assert.Throws<InvalidOperationException>(() => BffSnapshot.ResolveOwnedRedirect(Owner, new Uri(location, UriKind.RelativeOrAbsolute)));

    [Fact]
    public void OwnedRelativeRedirectKeepsTheSameAuthority()
        => Assert.Equal(Owner.Authority, BffSnapshot.ResolveOwnedRedirect(Owner, new Uri("/account/login?returnUrl=%2Fadmin%2F", UriKind.Relative)).Authority);

    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    public void TotpUsesKnownRfc6238Sha1SixDigitVectors(long unixTime, string expected)
        => Assert.Equal(expected, BffSnapshot.TotpCode(Encoding.ASCII.GetBytes("12345678901234567890"), DateTimeOffset.FromUnixTimeSeconds(unixTime)));
}
