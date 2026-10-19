namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>全局安全响应头；CSP 只为 OpenIddict form_post 自动提交脚本放行固定 hash。</summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    private const string FormPostScriptHash = "'sha256-j7OoGArf6XW6YY4cAyS3riSSvrJRqpSi1fOF9vQ5SrI='";

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        var formPostAuthorization = context.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase)
            && string.Equals(context.Request.Query["response_mode"], "form_post", StringComparison.Ordinal);
        headers["Content-Security-Policy"] = formPostAuthorization
            ? $"default-src 'self'; script-src 'self' {FormPostScriptHash}; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
            : "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        // HSTS：边缘 Caddy 已下发同款，应用层补齐覆盖绕过边缘直连端口（如容器网络内直达）
        // 的场景——双层一致，浏览器对两种入口都固定 https。仅在 https 请求上无条件下发：
        // http 明文响应携带 STS 头无效且徒增噪音。
        if (context.Request.IsHttps)
        {
            headers.StrictTransportSecurity = "max-age=31536000; includeSubDomains";
        }

        await next(context);
    }
}
