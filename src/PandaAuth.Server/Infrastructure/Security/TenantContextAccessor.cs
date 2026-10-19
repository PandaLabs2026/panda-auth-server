using Microsoft.AspNetCore.Http;
using PandaAuth.Server.Configuration;
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
    public async Task InvokeAsync(
        HttpContext context,
        ITenantHostResolver resolver,
        TenantContextAccessor accessor,
        TenantRoutingOptions options)
    {
        // 默认关闭：既有单租户部署（无 bindings）行为不变。启用后规范主机必须能解析，
        // 未登记/非 Ready 一律 fail-closed，不能静默放行到无租户上下文的路径。
        if (!options.Enabled ||
            !TenantCanonicalHost.TryParse(context.Request.Host.Host, out _, out _, out _))
        {
            await next(context);
            return;
        }

        try
        {
            accessor.Current = resolver.Resolve(context.Request);
        }
        catch (TenantContextException exception)
        {
            context.Response.StatusCode = StatusCodes.Status421MisdirectedRequest;
            await context.Response.WriteAsJsonAsync(new { error = exception.Code });
            return;
        }

        await next(context);
    }
}
