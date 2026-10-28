using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace PandaAuth.ReadinessHarness;

/// <summary>Component-only native smoke. Never produces controlled restore assertions.</summary>
public static class ControlledTransportSmoke
{
    public static async Task<int> Run(ControlledTransportInput input)
    {
        var directory = ControlledTransport.Initialize(input);
        var applications = new List<WebApplication>();
        try
        {
            foreach (var (component, port) in new[] { ("server",input.Spec.ServerPort),("admin",input.Spec.AdminPort),("me",input.Spec.MePort) })
            {
                var builder = WebApplication.CreateSlimBuilder([]); builder.Logging.ClearProviders();
                builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, port));
                var app = builder.Build(); applications.Add(app);
                app.Run(context => context.Response.WriteAsJsonAsync(new { component,
                    proto=context.Request.Headers["X-Forwarded-Proto"].ToString(), forwarded=context.Request.Headers["X-Forwarded-For"].ToString() }));
                await app.StartAsync();
            }
            using var leaf = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(directory,"proxy.pfx"),input.PfxPassword);
            var proxy = ControlledTransport.Application(input.Spec,leaf); applications.Add(proxy); await proxy.StartAsync();
            using var root = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(directory,"root.pem")));
            using var client = ControlledTransport.Client(root);
            foreach (var (path, component) in new[] { ("/healthz","server"),("/admin/healthz","admin"),("/me/healthz","me") })
            {
                using var request = new HttpRequestMessage(HttpMethod.Get,new Uri(new Uri(input.Spec.Issuer),path));
                request.Headers.Add("X-Forwarded-Proto","http"); request.Headers.Add("X-Forwarded-For","192.0.2.10");
                using var response = await client.SendAsync(request); response.EnsureSuccessStatusCode();
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                if (json.RootElement.GetProperty("component").GetString()!=component || json.RootElement.GetProperty("proto").GetString()!="https" ||
                    json.RootElement.GetProperty("forwarded").GetString()!="127.0.0.1") throw new InvalidOperationException();
            }
            async Task Reject(HttpClient candidate, Uri uri)
            {
                try { using var response=await candidate.GetAsync(uri); }
                catch (HttpRequestException) { return; }
                throw new InvalidOperationException("controlled_negative_tls_failed");
            }
            await Reject(client,new Uri("https://localhost/healthz"));
            var other = ControlledTransport.Certificates(input.Spec,input.PfxPassword);
            using var wrongRoot = X509Certificate2.CreateFromPem(other.RootPem);
            using var wrongClient = ControlledTransport.Client(wrongRoot);
            await Reject(wrongClient,new Uri(input.Spec.Issuer));
            using var connection = new TcpClient(); await connection.ConnectAsync(IPAddress.Loopback,443);
            using var tls = new SslStream(connection.GetStream());
            var policy = new X509ChainPolicy { TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.NoCheck };
            policy.CustomTrustStore.Add(root);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost=new Uri(input.Spec.Issuer).Host, CertificateChainPolicy=policy });
            await tls.WriteAsync(Encoding.ASCII.GetBytes("GET /healthz HTTP/1.1\r\nHost: foreign.example\r\nConnection: close\r\n\r\n"));
            using var reader=new StreamReader(tls);
            if (!(await reader.ReadLineAsync() ?? "").StartsWith("HTTP/1.1 421",StringComparison.Ordinal)) throw new InvalidOperationException();
            Console.WriteLine("{\"schema\":1,\"valid\":true,\"scope\":\"transport-component-only\",\"originalHostTls\":true,\"threeRoutes\":true,\"wrongHostRejected\":true,\"wrongCaRejected\":true,\"foreignAuthorityRejected\":true,\"forwardedHeadersReplaced\":true}");
            return 0;
        }
        finally { foreach(var app in applications.AsEnumerable().Reverse()) { await app.StopAsync(); await app.DisposeAsync(); } }
    }
}
