using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;

namespace PandaAuth.Server.Infrastructure.Security;

internal static class TenantForwardedHeaders
{
    private const string NetworkModeKey = "PANDA_AUTH_TENANT_NETWORK_MODE";
    private const string TrustedProxyKey = "PANDA_AUTH_TRUSTED_PROXY";

    public static void Configure(ForwardedHeadersOptions options, IConfiguration configuration)
    {
        var mode = configuration[NetworkModeKey];
        var trustedProxyValue = configuration[TrustedProxyKey];

        if (string.IsNullOrEmpty(mode))
        {
            if (!string.IsNullOrWhiteSpace(trustedProxyValue))
            {
                throw new InvalidOperationException($"{TrustedProxyKey} requires {NetworkModeKey}=bridge.");
            }

            options.KnownProxies.Add(IPAddress.Loopback);
            options.KnownProxies.Add(IPAddress.IPv6Loopback);
            return;
        }

        if (!string.Equals(mode, "bridge", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unsupported {NetworkModeKey}: {mode}.");
        }

        if (!IPAddress.TryParse(trustedProxyValue, out var trustedProxy)
            || trustedProxy.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new InvalidOperationException($"{TrustedProxyKey} must be one IPv4 address in bridge mode.");
        }

        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Add(trustedProxy);
    }
}
