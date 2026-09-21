using OpenIddict.Server;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// Explicit refresh-token replay policy. Keeping this out of the registration lambda
/// makes the security invariant testable and prevents an OpenIddict upgrade from
/// silently changing the intended behavior.
/// </summary>
internal static class RefreshTokenPolicy
{
    internal static readonly TimeSpan ReuseLeeway = TimeSpan.FromSeconds(5);

    internal static void Configure(OpenIddictServerOptions options)
    {
        // Rolling refresh tokens are the secure default. A redeemed token is only
        // accepted during this short window to tolerate concurrent client retries.
        options.DisableRollingRefreshTokens = false;
        options.RefreshTokenReuseLeeway = ReuseLeeway;
    }
}
