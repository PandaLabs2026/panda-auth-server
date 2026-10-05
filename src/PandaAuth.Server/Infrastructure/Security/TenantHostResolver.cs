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
            // IdP 只在自身产品（t####-auth）主机上产生租户上下文；PandaAssistant/Oasis 绑定
            // 仅供种子回调白名单展开（DbSeeder），不得让 IdP 响应非本产品主机（PANDA-INFRA-R1）。
            if (binding.Product != TenantProduct.PandaAuth)
                continue;
            TenantId tenantId;
            try
            {
                tenantId = TenantId.Parse(binding.TenantId);
            }
            catch (FormatException exception)
            {
                throw new InvalidOperationException($"Invalid tenant route binding: {binding.TenantId}.", exception);
            }

            var canonicalHost = TenantCanonicalHost.For(tenantId, binding.Product, binding.Zone);
            if (!string.Equals(canonicalHost, host, StringComparison.OrdinalIgnoreCase))
                continue;
            if (binding.RouteRevision < 1)
                throw new InvalidOperationException($"Invalid route revision for {canonicalHost}.");
            if (binding.State is not TenantRouteState.Ready)
                throw new TenantContextException(TenantContextErrors.RouteNotReady,
                    $"Tenant route is not ready: {canonicalHost} ({binding.State}).");

            return new TenantContext(tenantId, binding.Product, binding.Zone, canonicalHost, binding.RouteRevision, binding.State);
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

        // 同租户同分区的任一产品规范主机上的回调均放行（跨产品单点登录面）。
        return Enum.GetValues<TenantProduct>().Any(product =>
            string.Equals(redirectUri.Host, TenantCanonicalHost.For(context.TenantId, product, context.Zone), StringComparison.OrdinalIgnoreCase));
    }
}
