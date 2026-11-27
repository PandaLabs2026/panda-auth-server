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

        // 自定义 scheme 回跳（0.55.1，RFC 8252 公共客户端形态）：原生 App（asst-mobile）
        // 经 panda://callback 接收授权码。安全由 OpenIddict 白名单精确匹配 + PKCE（S256 强制）
        // + state 保证；scheme 抢注无法兑换令牌。租户主机校验仅对 https 有意义（scheme 无
        // 主机语义），此处放行 panda scheme 的精确 host 形态。
        if (string.Equals(redirectUri.Scheme, "panda", StringComparison.OrdinalIgnoreCase)
            && string.Equals(redirectUri.Host, "callback", StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.Equals(redirectUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;

        // Portal uses the tenant host without a product label. OpenIddict still
        // requires an exact registered redirect URI before this tenant check.
        // ADR-056 追记四: apex-form tenants (empty zone) use the bare apex portal host.
        var portalHost = context.IsApexForm
            ? TenantCanonicalHost.PortalApexHost(context.TenantId)
            : $"{context.TenantId.Value}.{context.Zone}.{TenantCanonicalHost.ZoneSuffix}";
        if (string.Equals(redirectUri.Host, portalHost, StringComparison.OrdinalIgnoreCase))
            return true;

        // 同租户同分区的任一产品规范主机上的回调均放行（跨产品单点登录面）；
        // apex 上下文(zone 空串)经 For 自动取 apex 形态，分区上下文取分区形态。
        // 标签双收（meta ADR-092）：并存窗口内各产品被接受的主机形态都放行（目前多出熊猫助理的 -pandy）。
        return Enum.GetValues<TenantProduct>()
            .SelectMany(product => TenantCanonicalHost.AcceptedHosts(context.TenantId, product, context.Zone))
            .Any(host => string.Equals(redirectUri.Host, host, StringComparison.OrdinalIgnoreCase)); // F2 收口
    }
}
