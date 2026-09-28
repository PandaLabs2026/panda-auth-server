using Microsoft.AspNetCore.Http;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

public interface ITenantContextAccessor
{
    TenantContext? Current { get; }
}

public sealed class TenantContextAccessor : ITenantContextAccessor
{
    public TenantContext? Current { get; internal set; }
}

public sealed class TenantHostMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, ITenantHostResolver resolver, TenantContextAccessor accessor)
    {
        if (LooksLikeTenantHost(context.Request.Host.Host))
            accessor.Current = resolver.Resolve(context.Request);
        await next(context);
    }

    private static bool LooksLikeTenantHost(string host) =>
        host.StartsWith("t", StringComparison.OrdinalIgnoreCase)
        && host.Length > 6
        && char.IsDigit(host[1])
        && char.IsDigit(host[2])
        && char.IsDigit(host[3])
        && char.IsDigit(host[4])
        && host[5] == '.';
}
