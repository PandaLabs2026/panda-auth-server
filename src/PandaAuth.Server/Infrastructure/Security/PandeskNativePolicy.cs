using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed class PandeskNativePolicy(IOptions<AuthOptions> options, IHostEnvironment environment)
{
    public bool AllowsHost(TenantContext? tenant, HttpRequest request)
    {
        var auth = options.Value;
        return auth.PandeskNative.Enabled && environment.IsDevelopment() && auth.TenantRouting.Enabled
            && tenant is { Product: TenantProduct.PandaAuth, State: TenantRouteState.Ready }
            && request.IsHttps
            && Uri.TryCreate(auth.Issuer, UriKind.Absolute, out var issuer)
            && issuer.Scheme == Uri.UriSchemeHttps && issuer.AbsolutePath == "/"
            && string.Equals(issuer.Host, tenant.CanonicalHost, StringComparison.OrdinalIgnoreCase)
            && string.Equals(issuer.Host, request.Host.Host, StringComparison.OrdinalIgnoreCase)
            && issuer.Port == (request.Host.Port ?? 443);
    }

    public static bool IsLoopbackCallback(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Port is > 0 and <= 65535
        && string.Equals(value, $"http://127.0.0.1:{uri.Port}{PandeskNativeIdentity.CallbackPath}", StringComparison.Ordinal);
}
