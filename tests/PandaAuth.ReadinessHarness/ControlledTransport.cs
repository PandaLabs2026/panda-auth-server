using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;

namespace PandaAuth.ReadinessHarness;

public sealed record ControlledTransportSpec(int Schema, string Attempt, string SourceBindingSha256, string Issuer,
    int ServerPort, int AdminPort, int MePort);
public sealed record ControlledTransportInput(ControlledTransportSpec Spec, string PfxPassword = "", string ProbePath = "/healthz");
public sealed record ControlledTlsMaterial(string RootPem, byte[] Pfx);

/// <summary>Original-URL TLS inside a verified network-none clone. Never a restore success proof.</summary>
public static class ControlledTransport
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 16
    };
    [DllImport("libc")] private static extern uint geteuid();
    private static void Require(bool value) { if (!value) throw new InvalidOperationException("controlled_transport_failed"); }

    public static void Validate(ControlledTransportSpec spec)
    {
        Require(spec.Schema == 1 && Regex.IsMatch(spec.Attempt, "^[a-f0-9]{32}$") && Regex.IsMatch(spec.SourceBindingSha256, "^[a-f0-9]{64}$"));
        Require(Uri.TryCreate(spec.Issuer, UriKind.Absolute, out var issuer) && issuer.Scheme == "https" && issuer.Port == 443 &&
            issuer.UserInfo.Length == 0 && issuer.AbsolutePath == "/" && issuer.Query.Length == 0 && issuer.Fragment.Length == 0 &&
            issuer.HostNameType == UriHostNameType.Dns && issuer.Host.Contains('.') && spec.Issuer.All(character => character < 128) &&
            spec.Issuer == spec.Issuer.Trim() && !spec.Issuer.Contains('\\') && !spec.Issuer.Contains('%'));
        var ports = new[] { spec.ServerPort, spec.AdminPort, spec.MePort };
        Require(ports.All(port => port is >= 1024 and <= 65535 && port != 55432) && ports.Distinct().Count() == 3);
    }

    public static string Canonical(ControlledTransportSpec spec) { Validate(spec); return JsonSerializer.Serialize(spec, Json); }
    public static ControlledTransportInput Parse(string value)
    {
        if (value.Length > 65536) throw new JsonException();
        using var document = JsonDocument.Parse(value, new JsonDocumentOptions { MaxDepth = 16 });
        static void Unique(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in element.EnumerateObject()) { if (!names.Add(property.Name)) throw new JsonException(); Unique(property.Value); }
            }
            else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) Unique(item);
        }
        Unique(document.RootElement);
        return JsonSerializer.Deserialize<ControlledTransportInput>(value, Json) ?? throw new JsonException();
    }

    public static string Guard(ControlledTransportSpec spec)
    {
        Validate(spec);
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("controlled_transport_failed");
        Require(geteuid() == 1654 && Environment.GetEnvironmentVariable("PANDA_AUTH_CONTROLLED_ATTEMPT") == spec.Attempt &&
            Environment.GetEnvironmentVariable("PANDA_AUTH_CONTROLLED_SPEC_SHA256") == Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(spec)))));
        Require(NetworkInterface.GetAllNetworkInterfaces().All(item => item.NetworkInterfaceType == NetworkInterfaceType.Loopback));
        var addresses = Dns.GetHostAddresses(new Uri(spec.Issuer).DnsSafeHost);
        Require(addresses.Length > 0 && addresses.All(IPAddress.IsLoopback));
        Require(Directory.Exists("/fixture") && new DirectoryInfo("/fixture").LinkTarget is null &&
            File.GetUnixFileMode("/fixture") == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute));
        return "/fixture/"+spec.Attempt;
    }

    public static ControlledTlsMaterial Certificates(ControlledTransportSpec spec, string password)
    {
        Validate(spec); Require(password.Length is >= 24 and <= 256);
        var now = DateTimeOffset.UtcNow;
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=panda-auth-controlled-"+spec.Attempt, rootKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var root = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN="+new Uri(spec.Issuer).DnsSafeHost, leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName(new Uri(spec.Issuer).DnsSafeHost);
        leafRequest.CertificateExtensions.Add(names.Build());
        using var issued = leafRequest.Create(root, now.AddMinutes(-4), now.AddHours(20), RandomNumberGenerator.GetBytes(16));
        using var leaf = issued.CopyWithPrivateKey(leafKey);
        return new(root.ExportCertificatePem(), leaf.Export(X509ContentType.Pfx, password));
    }

    private static void WriteNew(string path, byte[] data)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        stream.Write(data); stream.Flush(true);
    }

    public static string Initialize(ControlledTransportInput input)
    {
        var directory = Guard(input.Spec);
        Require(!Directory.Exists(directory) && !File.Exists(directory));
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        WriteNew(Path.Combine(directory, "transport.json"), Encoding.UTF8.GetBytes(Canonical(input.Spec)));
        var tls = Certificates(input.Spec, input.PfxPassword);
        WriteNew(Path.Combine(directory, "root.pem"), Encoding.ASCII.GetBytes(tls.RootPem));
        WriteNew(Path.Combine(directory, "proxy.pfx"), tls.Pfx);
        return directory;
    }

    public static int SelectPort(ControlledTransportSpec spec, PathString path) => path.StartsWithSegments("/admin") ? spec.AdminPort :
        path.StartsWithSegments("/me") ? spec.MePort : spec.ServerPort;
    public static Uri Target(ControlledTransportSpec spec, PathString path, QueryString query) =>
        new UriBuilder("http", "127.0.0.1", SelectPort(spec,path)) { Path = path.Value, Query = query.Value?.TrimStart('?') }.Uri;
    private static readonly HashSet<string> Hop = new(StringComparer.OrdinalIgnoreCase)
        { "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade" };

    public static WebApplication Application(ControlledTransportSpec spec, X509Certificate2 leaf)
    {
        Validate(spec);
        var builder = WebApplication.CreateSlimBuilder([]); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => { server.Limits.MaxRequestBodySize = 4*1024*1024;
            server.Listen(IPAddress.Loopback, 443, options => options.UseHttps(leaf)); });
        builder.Services.AddSingleton(_ => new HttpClient(new SocketsHttpHandler
            { AllowAutoRedirect = false, UseCookies = false, UseProxy = false, MaxConnectionsPerServer = 8 }) { Timeout = TimeSpan.FromSeconds(30) });
        var app = builder.Build(); var client = app.Services.GetRequiredService<HttpClient>();
        app.Run(async context =>
        {
            if (!string.Equals(context.Request.Host.Host, new Uri(spec.Issuer).Host, StringComparison.OrdinalIgnoreCase) ||
                context.Request.Host.Port is not (null or 443)) { context.Response.StatusCode = 421; return; }
            using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), Target(spec, context.Request.Path, context.Request.QueryString));
            if (context.Request.ContentLength > 0 || context.Request.Headers.ContainsKey("Transfer-Encoding")) request.Content = new StreamContent(context.Request.Body);
            foreach (var header in context.Request.Headers)
            {
                if (Hop.Contains(header.Key) || header.Key.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) || header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray())) request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
            request.Headers.Host = context.Request.Host.Value;
            request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https"); request.Headers.TryAddWithoutValidation("X-Forwarded-For", "127.0.0.1");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
            context.Response.StatusCode = (int)response.StatusCode;
            foreach (var header in response.Headers.Concat(response.Content.Headers)) if (!Hop.Contains(header.Key)) context.Response.Headers[header.Key] = header.Value.ToArray();
            await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
        });
        return app;
    }

    public static HttpClient Client(X509Certificate2 root)
    {
        var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
        policy.CustomTrustStore.Add(root);
        return new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false,
            SslOptions = { CertificateChainPolicy = policy } }) { Timeout = TimeSpan.FromSeconds(8) };
    }

    public static async Task<int> Dispatch(string command, string line)
    {
        try
        {
            var input = Parse(line); var directory = Guard(input.Spec);
            if (command == "--controlled-transport-smoke-stdin") return await ControlledTransportSmoke.Run(input);
            if (command == "--controlled-proxy-stdin")
            {
                directory = Initialize(input);
                using var leaf = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(directory, "proxy.pfx"), input.PfxPassword);
                await using var app = Application(input.Spec, leaf);
                await app.StartAsync(); Console.WriteLine(JsonSerializer.Serialize(new { schema=1, ready=true, scope="controlled-transport-only" }, Json));
                await app.WaitForShutdownAsync(); return 0;
            }
            Require(command == "--controlled-probe-stdin" && input.ProbePath is "/healthz" or "/admin/healthz" or "/me/healthz");
            Require(new DirectoryInfo(directory).LinkTarget is null && File.ReadAllText(Path.Combine(directory,"transport.json")) == Canonical(input.Spec));
            using var root = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(directory,"root.pem")));
            using var client = Client(root);
            using var response = await client.GetAsync(new Uri(new Uri(input.Spec.Issuer),input.ProbePath));
            Require(response.IsSuccessStatusCode);
            Console.WriteLine(JsonSerializer.Serialize(new { schema=1, valid=true, scope="controlled-transport-only" }, Json)); return 0;
        }
        catch { Console.WriteLine("{\"schema\":1,\"valid\":false,\"error\":\"controlled_transport_failed\"}"); return 2; }
    }
}
