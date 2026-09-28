using Microsoft.AspNetCore.Http;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed class TenantContextException(string code, string message) : InvalidOperationException(message)
{
    public string Code { get; } = code;
}

public interface ITenantHostResolver
{
    TenantContext Resolve(HttpRequest request);
}

public sealed class TenantHostResolver(TenantRoutingOptions options) : ITenantHostResolver
{
    public TenantContext Resolve(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var host = request.Host.Host;
        if (string.IsNullOrWhiteSpace(host))
            throw Unknown(host);

        foreach (var binding in options.Bindings)
        {
            TenantId tenantId;
            try
            {
                tenantId = TenantId.Parse(binding.TenantId);
            }
            catch (FormatException exception)
            {
                throw new InvalidOperationException($"Invalid tenant route binding: {binding.TenantId}.", exception);
            }

            var canonicalHost = TenantCanonicalHost.For(tenantId, binding.Product);
            if (!string.Equals(canonicalHost, host, StringComparison.OrdinalIgnoreCase))
                continue;
            if (binding.RouteRevision < 1)
                throw new InvalidOperationException($"Invalid route revision for {canonicalHost}.");
            if (binding.State is not TenantRouteState.Ready)
                throw new TenantContextException(TenantContextErrors.RouteNotReady,
                    $"Tenant route is not ready: {canonicalHost} ({binding.State}).");

            return new TenantContext(tenantId, binding.Product, canonicalHost, binding.RouteRevision, binding.State);
        }

        throw Unknown(host);
    }

    private static TenantContextException Unknown(string host) =>
        new(TenantContextErrors.UnknownHost, $"Unknown tenant host: {host}.");
}

public sealed class TenantRedirectPolicy
{
    public bool IsAllowed(TenantContext context, Uri redirectUri)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(redirectUri);
        if (!redirectUri.IsAbsoluteUri || redirectUri.UserInfo.Length > 0 || !string.IsNullOrEmpty(redirectUri.Fragment))
            return false;
        if (!string.Equals(redirectUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;

        return Enum.GetValues<TenantProduct>().Any(product =>
            string.Equals(redirectUri.Host, TenantCanonicalHost.For(context.TenantId, product), StringComparison.OrdinalIgnoreCase));
    }
}
