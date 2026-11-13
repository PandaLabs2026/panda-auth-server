using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace PandaAuth.Tests;

public sealed class CloudControlServiceJointTests
{
    [CloudControlServiceJointFact]
    public async Task Actual_Auth_tokens_reach_actual_Service_with_current_application_object_and_dependency_boundaries()
    {
        await using var auth=await CloudControlProtocolTests.Fixture.CreateAsync();using var browser=auth.Browser();
        await using var joint=await Joint.StartAsync(auth);
        var console=(await auth.TokenAsync(browser,"cloud-console-web",["cloud.resources.read","cloud.resources.manage","fleet.approve"])).Access;
        var fleet=(await auth.TokenAsync(browser,"fleet-admin-web",["fleet.read","cloud.health.check"])).Access;
        var operation=(await auth.TokenAsync(browser,"cloud-operation-web",["cloud.resources.summary.read"])).Access;
        var noAudience=(await auth.TokenAsync(browser,"cloud-console-web",[])).Access;
        await joint.ExpectAsync(null,"/resources/v1/services",HttpStatusCode.Unauthorized);
        await joint.ExpectAsync(noAudience,"/resources/v1/services",HttpStatusCode.Unauthorized);
        await joint.ExpectAsync(console,"/resources/v1/services",HttpStatusCode.Forbidden);
        await joint.CommandAsync("grant-platform");
        await joint.ExpectAsync(console,"/resources/v1/services",HttpStatusCode.OK);
        await joint.ExpectTenantApprovalRefusedAsync(console);
        await joint.CommandAsync("assert-no-tenant-write");
        await joint.ExpectAsync(fleet,"/resources/v1/services",HttpStatusCode.Forbidden);
        await joint.ExpectAsync(operation,"/resources/v1/services",HttpStatusCode.Forbidden);
        await joint.ExpectAsync(console,"/resources/v1/tenant-contexts/t0001",HttpStatusCode.Forbidden);
        var summary=await joint.ExpectAsync(operation,"/resources/v1/platform-summaries",HttpStatusCode.OK);
        Assert.DoesNotContain("private.invalid",summary);Assert.DoesNotContain("serverId",summary);Assert.DoesNotContain("tenantId",summary);
        const string owned="/resources/v1/tenant-contexts/t0001/deployments/20000000-0000-4000-8000-000000000053";
        await joint.ExpectAsync(fleet,owned,HttpStatusCode.OK);
        await joint.CommandAsync("withdraw-fleet-app");await joint.ExpectAsync(fleet,owned,HttpStatusCode.Forbidden);
        await joint.CommandAsync("restore-fleet-app");await joint.ExpectAsync(fleet,owned,HttpStatusCode.OK);
        await joint.ExpectAsync(fleet,"/resources/v1/tenant-contexts/t0002/deployments/20000000-0000-4000-8000-000000000056",HttpStatusCode.NotFound);
        const string shared="/resources/v1/tenant-contexts/t0001/endpoints/30000000-0000-4000-8000-000000000054";
        var health=await joint.ExpectAsync(fleet,shared,HttpStatusCode.OK);
        Assert.Contains("health-summary",health);Assert.DoesNotContain("private-shared.invalid",health);
        await joint.CommandAsync("revoke-shared");await joint.ExpectAsync(fleet,shared,HttpStatusCode.NotFound);
        await joint.CommandAsync("revoke-platform");await joint.ExpectAsync(console,"/resources/v1/services",HttpStatusCode.Forbidden);
        joint.Unavailable=true;await joint.ExpectAsync(fleet,owned,HttpStatusCode.ServiceUnavailable);
        joint.Unavailable=false;await joint.ExpectAsync(fleet,owned,HttpStatusCode.OK);
        await joint.CommandAsync("revoke-tenant");await joint.ExpectAsync(fleet,owned,HttpStatusCode.NotFound);
        await auth.RevokeAsync("cloud-operation-web");
        Assert.False((await auth.InspectAsync(browser,operation)).GetProperty("active").GetBoolean());
        await joint.ExpectAsync(operation,"/resources/v1/platform-summaries",HttpStatusCode.Unauthorized);
    }

    internal sealed class Joint : IAsyncDisposable
    {
        private readonly string root,runId;
        private readonly X509Certificate2 certificate;
        private WebApplication? authBridge;
        private Process? process;
        private Task<string>? errors;
        private HttpClient? service;
        private bool ready;
        internal volatile bool Unavailable;
        private Joint()
        {
            if(!OperatingSystem.IsLinux())throw new InvalidOperationException();
            runId=Guid.NewGuid().ToString("N");root=Path.Combine(Path.GetTempPath(),"cloud-control-joint-"+runId);
            Directory.CreateDirectory(root);File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
            using var key=RSA.Create(2048);var request=new CertificateRequest("CN=auth.appliket.com",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            var names=new SubjectAlternativeNameBuilder();names.AddDnsName("auth.appliket.com");names.AddDnsName("localhost");names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
            certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddHours(1));
            Write("run-id",runId);Write("certificate.pem",certificate.ExportCertificatePem());Write("key.pem",key.ExportPkcs8PrivateKeyPem());
        }
        private void Write(string name,string text)
        {
            var path=Path.Combine(root,name);File.WriteAllText(path,text);
            if(OperatingSystem.IsLinux())File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        }
        internal static async Task<Joint> StartAsync(CloudControlProtocolTests.Fixture auth)
        {
            var joint=new Joint();
            try
            {
                var transport=new HttpClient(auth.Transport());
                joint.transport=transport;
                var builder=WebApplication.CreateSlimBuilder();builder.Logging.ClearProviders();
                builder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0,listen=>listen.UseHttps(joint.certificate)));
                joint.authBridge=builder.Build();
                joint.authBridge.Run(async context=>
                {
                    if(joint.Unavailable){context.Response.StatusCode=503;return;}
                    if(!context.Request.Path.StartsWithSegments("/.well-known")&&context.Request.Path!="/connect/introspect")
                    {context.Response.StatusCode=404;return;}
                    using var request=new HttpRequestMessage(new HttpMethod(context.Request.Method),"https://auth.appliket.com"+context.Request.Path+context.Request.QueryString);
                    if(context.Request.ContentLength is >0){using var bytes=new MemoryStream();await context.Request.Body.CopyToAsync(bytes);request.Content=new ByteArrayContent(bytes.ToArray());}
                    foreach(var header in context.Request.Headers)
                        if(!new[]{"Host","Connection","Content-Length"}.Contains(header.Key,StringComparer.OrdinalIgnoreCase)
                            &&!request.Headers.TryAddWithoutValidation(header.Key,header.Value.ToArray()))request.Content?.Headers.TryAddWithoutValidation(header.Key,header.Value.ToArray());
                    using var response=await transport.SendAsync(request,context.RequestAborted);
                    context.Response.StatusCode=(int)response.StatusCode;
                    foreach(var header in response.Headers.Concat(response.Content.Headers))
                        if(header.Key is not "Transfer-Encoding" and not "Connection")context.Response.Headers[header.Key]=header.Value.ToArray();
                    await response.Content.CopyToAsync(context.Response.Body,context.RequestAborted);
                });
                await joint.authBridge.StartAsync();
                var authAddress=joint.authBridge.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
                var start=new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")??"dotnet")
                    {RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
                var directory=Environment.GetEnvironmentVariable("CLOUD_CONTROL_SERVICE_FIXTURE_DIRECTORY")!;
                start.WorkingDirectory=directory; // WAF reads this build's MvcTestingAppManifest.json.
                start.ArgumentList.Add(Path.Combine(directory,"PandaCloud.Service.Integration.Tests.dll"));start.ArgumentList.Add("--cloud-control-joint-stdin");
                start.Environment.Clear();start.Environment["PATH"]=Environment.GetEnvironmentVariable("PATH");
                foreach(var key in new[]{"TMPDIR","TMP","TEMP","FLEET_TEST_DATABASE"})start.Environment[key]=Environment.GetEnvironmentVariable(key);
                start.Environment["CLOUD_CONTROL_JOINT_RUN"]=joint.runId;
                joint.process=Process.Start(start)!;joint.errors=joint.process.StandardError.ReadToEndAsync();
                await joint.process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new {Root=joint.root,RunId=joint.runId,AuthPort=new Uri(authAddress).Port,Subject=auth.Subject,IntrospectionSecret="api-fixture-secret"}));
                await joint.process.StandardInput.FlushAsync();
                var line=await joint.process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(90));
                if(line is null)
                {
                    await joint.process.WaitForExitAsync();
                    throw new InvalidOperationException("Service joint fixture exited "+joint.process.ExitCode+": "+await joint.errors);
                }
                using var ready=JsonDocument.Parse(line);Assert.Equal("cloud-control-joint-ready",ready.RootElement.GetProperty("state").GetString());
                Assert.StartsWith("7.7.2",ready.RootElement.GetProperty("validationVersion").GetString());
                var address=ready.RootElement.GetProperty("address").GetString()!;var uri=new Uri(address);
                Assert.Equal("https",uri.Scheme);Assert.Equal("127.0.0.1",uri.Host);Assert.InRange(uri.Port,1024,65535);
                var pin=joint.certificate.GetCertHashString(HashAlgorithmName.SHA256);
                joint.service=new HttpClient(new HttpClientHandler {AllowAutoRedirect=false,UseCookies=false,UseProxy=false,
                    ServerCertificateCustomValidationCallback=(_,cert,_,_)=>cert?.GetCertHashString(HashAlgorithmName.SHA256)==pin})
                    {BaseAddress=uri,Timeout=TimeSpan.FromSeconds(15)};
                joint.ready=true;
                // Keep the Auth TestServer transport alive until the bridge stops.
                return joint;
            }
            catch {await joint.DisposeAsync();throw;}
        }
        private HttpClient? transport;
        internal async Task<string> ExpectAsync(string? token,string path,HttpStatusCode expected)
        {
            using var request=new HttpRequestMessage(HttpMethod.Get,path);if(token is not null)request.Headers.Authorization=new("Bearer",token);
            using var response=await service!.SendAsync(request);Assert.Equal(expected,response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore==true);
            return await response.Content.ReadAsStringAsync();
        }
        internal async Task CommandAsync(string command)
        {
            await process!.StandardInput.WriteLineAsync(command);await process.StandardInput.FlushAsync();
            Assert.Equal("ack:"+command,await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15)));
        }
        internal async Task ExpectTenantApprovalRefusedAsync(string token)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,"/lifecycle/v1/plans/40000000-0000-4000-8000-000000000053/approve")
                {Content=new StringContent("{}",System.Text.Encoding.UTF8,"application/json")};
            request.Headers.Authorization=new("Bearer",token);request.Headers.Add("Idempotency-Key","joint-resource-cannot-approve-tenant");
            using var response=await service!.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore==true);
        }
        public async ValueTask DisposeAsync()
        {
            int? exit=null;
            service?.Dispose();
            if(process is not null)
            {
                process.StandardInput.Close();
                try {await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));}
                catch(TimeoutException){process.Kill(entireProcessTree:true);await process.WaitForExitAsync();}
                if(errors is not null)await errors;exit=process.ExitCode;process.Dispose();
            }
            if(authBridge is not null){await authBridge.StopAsync();await authBridge.DisposeAsync();}transport?.Dispose();certificate.Dispose();
            if(Directory.Exists(root))Directory.Delete(root,true);
            if(ready)Assert.Equal(0,exit); // Includes the child host/role/database disposal path.
        }
    }
}

internal sealed class CloudControlServiceJointFactAttribute : FactAttribute
{
    public CloudControlServiceJointFactAttribute()
    {
        if(!OperatingSystem.IsLinux()||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"))
            ||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("FLEET_TEST_DATABASE"))
            ||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUD_CONTROL_SERVICE_FIXTURE_DIRECTORY")))
            Skip="Explicit isolated Auth/Service joint inputs are required; not validated by ordinary profiles.";
    }
}
