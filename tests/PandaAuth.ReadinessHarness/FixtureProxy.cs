using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace PandaAuth.ReadinessHarness;

public sealed record ProxyRequest(string RunId, string UpstreamUri, string CertificateFile, string CertificatePassword, int Port, bool EnableBffs = false);

public static class FixtureProxy
{
    public static Uri SelectUpstream(Uri server, PathString path, bool enableBffs)
    {
        if (enableBffs && path.StartsWithSegments("/admin")) return new Uri("http://127.0.0.1:6001/");
        if (enableBffs && path.StartsWithSegments("/me")) return new Uri("http://127.0.0.1:6002/");
        return server;
    }
    public static Uri BuildTarget(Uri upstream, PathString path, QueryString query) =>
        new UriBuilder(upstream) { Path = path.Value, Query = query.Value?.TrimStart('?') }.Uri;
    private static readonly HashSet<string> HopHeaders = new(StringComparer.OrdinalIgnoreCase)
        { "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade" };

    public static async Task RunAsync(ProxyRequest settings)
    {
        if (!Regex.IsMatch(settings.RunId, "^[0-9a-f]{32}$") || settings.Port is < 20000 or > 65535 ||
            !Uri.TryCreate(settings.UpstreamUri, UriKind.Absolute, out var upstream) || upstream.Scheme != Uri.UriSchemeHttp ||
            upstream.Host != "panda-r1-server-" + settings.RunId || upstream.UserInfo.Length > 0 || upstream.Port != 8080 ||
            upstream.AbsolutePath != "/" || upstream.Query.Length > 0 || upstream.Fragment.Length > 0)
            throw new InvalidOperationException("readiness_proxy_admission_failed");
        using var certificate = X509CertificateLoader.LoadPkcs12FromFile(settings.CertificateFile, settings.CertificatePassword);
        var builder = WebApplication.CreateBuilder([]);
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => server.ListenAnyIP(settings.Port, listener => listener.UseHttps(certificate)));
        await using var app = builder.Build();
        using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false })
            { Timeout = TimeSpan.FromSeconds(30) };
        app.Run(async context =>
        {
            using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method),
                BuildTarget(SelectUpstream(upstream, context.Request.Path, settings.EnableBffs), context.Request.Path, context.Request.QueryString));
            if (context.Request.ContentLength > 0 || context.Request.Headers.ContainsKey("Transfer-Encoding"))
                request.Content = new StreamContent(context.Request.Body);
            foreach (var header in context.Request.Headers)
            {
                if (HopHeaders.Contains(header.Key) || header.Key.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) || header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                    request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
            request.Headers.Host = context.Request.Host.Value;
            request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", context.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
            context.Response.StatusCode = (int)response.StatusCode;
            foreach (var header in response.Headers.Concat(response.Content.Headers))
                if (!HopHeaders.Contains(header.Key)) context.Response.Headers[header.Key] = header.Value.ToArray();
            await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
        });
        await app.RunAsync();
    }
}
