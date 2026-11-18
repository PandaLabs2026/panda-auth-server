using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class CloudControlServiceJointTests
{
    [CloudControlConsoleBrowserJointFact]
    public async Task Actual_Console_browser_reads_catalog_and_runs_one_fresh_check()
    {
        await using var auth = await CloudControlProtocolTests.Fixture.CreateAsync(consoleBrowser:true);
        await using var joint = await Joint.StartAsync(auth, browserFlow:true);
        await joint.CommandAsync("grant-platform");
        await joint.CommandAsync("assert-no-browser-check");
        await joint.VerifyBrowserAsync(auth.Subject);
    }

    [CloudControlFleetBrowserJointFact]
    public async Task Actual_Console_and_Fleet_use_one_issuer_Service_and_check_queue()
    {
        await using var auth = await CloudControlProtocolTests.Fixture.CreateAsync(consoleBrowser:true);
        await using var joint = await Joint.StartAsync(auth, browserFlow:true);
        await joint.CommandAsync("grant-platform");
        await joint.CommandAsync("assert-no-browser-check");
        await joint.VerifyBrowserAsync(auth.Subject);
        await joint.VerifyBrowserAsync(auth.Subject, fleet:true);
    }

    [CloudControlOperationBrowserJointFact]
    public async Task Actual_three_apps_share_the_current_issuer_and_observation_source()
    {
        await using var auth=await CloudControlProtocolTests.Fixture.CreateAsync(consoleBrowser:true);
        var operation=Environment.GetEnvironmentVariable("CLOUD_CONTROL_OPERATION_BROWSER_CHECKOUT")!;
        var schema=Path.Combine(operation,"src/PandaCloud.Operation/Operations/schema.sql");
        await using var joint=await Joint.StartAsync(auth,browserFlow:true,operationSchema:schema);
        await joint.CommandAsync("grant-platform");
        await joint.CommandAsync("assert-no-browser-check");
        await joint.VerifyBrowserAsync(auth.Subject);
        await joint.VerifyBrowserAsync(auth.Subject,fleet:true);

        await joint.VerifyBrowserAsync(auth.Subject,collectSummary:async () =>
        {
            using var browser=auth.Browser();
            var token=(await auth.TokenAsync(browser,FirstPartyClients.CloudConsoleWeb,
                [CloudControlScopes.ResourcesRead,CloudControlScopes.HealthCheck])).Access;
            await joint.CommandAsync("grant-platform");
            await joint.CollectOperationObservationAsync(token);
        });
    }

    [CloudControlServiceJointFact]
    public async Task Actual_Auth_tokens_reach_actual_Service_with_current_application_object_and_dependency_boundaries()
    {
        await using var auth=await CloudControlProtocolTests.Fixture.CreateAsync();using var browser=auth.Browser();
        await using var joint=await Joint.StartAsync(auth);
        var console=(await auth.TokenAsync(browser,"cloud-console-web",["cloud.resources.read","cloud.resources.manage","fleet.approve"])).Access;
        Assert.False((await auth.InspectAsync(browser,console,FirstPartyClients.CloudOperationWeb)).GetProperty("active").GetBoolean());
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
        private Uri? authUri;
        private bool ready;
        internal volatile bool Unavailable;
        private Joint()
        {
            if(!OperatingSystem.IsLinux())throw new InvalidOperationException();
            runId=Guid.NewGuid().ToString("N");root=Path.Combine(Path.GetTempPath(),"cloud-control-joint-"+runId);
            Directory.CreateDirectory(root);File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
            var host=new Uri(PandaMadeScopes.CloudIssuer).Host;
            using var key=RSA.Create(2048);var request=new CertificateRequest("CN="+host,key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            var names=new SubjectAlternativeNameBuilder();names.AddDnsName(host);names.AddDnsName("localhost");names.AddIpAddress(IPAddress.Loopback);
            names.AddDnsName("console.pandacloud.cc");
            names.AddDnsName("fleet.pandacloud.cc");
            names.AddDnsName("operation.pandacloud.cc");
            request.CertificateExtensions.Add(names.Build());request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
            certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddHours(1));
            Write("run-id",runId);Write("certificate.pem",certificate.ExportCertificatePem());Write("key.pem",key.ExportPkcs8PrivateKeyPem());
        }
        private void Write(string name,string text)
        {
            var path=Path.Combine(root,name);File.WriteAllText(path,text);
            if(OperatingSystem.IsLinux())File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        }
        internal static async Task<Joint> StartAsync(CloudControlProtocolTests.Fixture auth,bool browserFlow=false,string? operationSchema=null)
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
                    var requestPath=context.Request.Path.Value;
                    var browserEndpoint=browserFlow && requestPath is "/account/login" or "/connect/authorize"
                        or "/connect/token" or "/connect/userinfo" or "/connect/par";
                    if(!context.Request.Path.StartsWithSegments("/.well-known")&&context.Request.Path!="/connect/introspect"&&!browserEndpoint)
                    {context.Response.StatusCode=404;return;}
                    using var request=new HttpRequestMessage(new HttpMethod(context.Request.Method),PandaMadeScopes.CloudIssuer.TrimEnd('/')+context.Request.Path+context.Request.QueryString);
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
                joint.authUri=new Uri(authAddress);
                var start=new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")??"dotnet")
                    {RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
                var directory=Environment.GetEnvironmentVariable("CLOUD_CONTROL_SERVICE_FIXTURE_DIRECTORY")!;
                start.WorkingDirectory=directory; // WAF reads this build's MvcTestingAppManifest.json.
                start.ArgumentList.Add(Path.Combine(directory,"PandaCloud.Service.Integration.Tests.dll"));start.ArgumentList.Add("--cloud-control-joint-stdin");
                start.Environment.Clear();start.Environment["PATH"]=Environment.GetEnvironmentVariable("PATH");
                foreach(var key in new[]{"TMPDIR","TMP","TEMP","FLEET_TEST_DATABASE"})start.Environment[key]=Environment.GetEnvironmentVariable(key);
                start.Environment["CLOUD_CONTROL_JOINT_RUN"]=joint.runId;
                joint.process=Process.Start(start)!;joint.errors=joint.process.StandardError.ReadToEndAsync();
                var input=JsonSerializer.SerializeToNode(new {Root=joint.root,RunId=joint.runId,AuthPort=joint.authUri.Port,Subject=auth.Subject,IntrospectionSecret="api-fixture-secret"})!.AsObject();
                if(browserFlow)input["BrowserCheck"]=true;
                if(operationSchema is not null)input["OperationSchema"]=operationSchema;
                await joint.process.StandardInput.WriteLineAsync(input.ToJsonString());
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
        internal async Task VerifyBrowserAsync(string subject,bool fleet=false,Func<Task>? collectSummary=null)
        {
            var application=collectSummary is not null?"operation":fleet?"fleet":"console";
            var checkout=Environment.GetEnvironmentVariable($"CLOUD_CONTROL_{application.ToUpperInvariant()}_BROWSER_CHECKOUT")!;
            var output=Environment.GetEnvironmentVariable("CLOUD_CONTROL_CONSOLE_BROWSER_EVIDENCE")!;
            var temporary=Path.GetTempPath();
            if(!Path.IsPathFullyQualified(checkout)||Path.GetFullPath(checkout)!=checkout
                ||Path.GetFileName(checkout)!="panda-cloud-"+application||!Directory.Exists(checkout)
                ||!Path.IsPathFullyQualified(output)||Path.GetDirectoryName(output)!=temporary.TrimEnd('/')
                ||!Directory.Exists(output)||new DirectoryInfo(output).LinkTarget is not null)
                throw new InvalidOperationException("The explicit private browser checkout and evidence directory are required.");
            Write("cert.pem",certificate.ExportCertificatePem());
            var bridge=Path.Combine(root,"bridge-ready.json");
            Write("bridge-ready.json",JsonSerializer.Serialize(new
            {
                browserApplication=application, consoleOrigin=$"https://{application}.pandacloud.cc/",
                issuer=PandaMadeScopes.CloudIssuer, authLoopbackPort=authUri!.Port,
                proxyPort=service!.BaseAddress!.Port, certificateSha256=certificate.GetCertHashString(HashAlgorithmName.SHA256),subject,
                tenantId=fleet?"t0001":null,endpointId=fleet?"30000000-0000-4000-8000-000000000053":null
            }));
            var start=new ProcessStartInfo("/usr/bin/node")
            {
                WorkingDirectory=checkout,UseShellExecute=false,
                RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true
            };
            start.ArgumentList.Add(Path.Combine(checkout,application switch
            {
                "operation"=>"tests/browser/platform-summary-current-auth.mjs",
                "fleet"=>"tests/browser/tenant-resources-current-auth.mjs",
                _=>"scripts/verify-resources-current-auth-browser.mjs",
            }));
            start.ArgumentList.Add(bridge);
            foreach(var name in new[]{"PANDA_AUTH_TEST_POSTGRES","PANDA_AUTH_TEST_SHARED_POSTGRES","FLEET_TEST_DATABASE"})
                start.Environment.Remove(name);
            using var browser=Process.Start(start)!;
            var errors=browser.StandardError.ReadToEndAsync();
            try
            {
                async Task ExpectSignal(string expected)
                {
                    var signal=await browser.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(90));
                    if(signal!=expected)throw new InvalidOperationException(application+" browser did not reach "+expected+": "+await errors);
                }
                async Task Continue(string command)
                {
                    await browser.StandardInput.WriteLineAsync(command);
                    await browser.StandardInput.FlushAsync();
                }
                if(collectSummary is not null)
                {
                    await ExpectSignal("OPERATION_SUMMARY_READ");
                    await CommandAsync("assert-two-browser-checks");
                    await collectSummary();
                    await Continue("fresh-observation");
                    await ExpectSignal("OPERATION_SUMMARY_FRESH");
                    await CommandAsync("revoke-operation-summary");
                    await Continue("summary-grant-withdrawn");
                }
                else
                {
                    await ExpectSignal(fleet?"FLEET_BROWSER_CHECK_COMPLETED":"CONSOLE_BROWSER_CHECK_COMPLETED");
                    await CommandAsync(fleet?"assert-two-browser-checks":"assert-one-browser-check");
                    await CommandAsync(fleet?"revoke-tenant":"revoke-platform");
                    await Continue(fleet?"tenant-grant-revoked":"platform-grant-revoked");
                }
                await browser.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(45));
                if(browser.ExitCode!=0)throw new InvalidOperationException(application+" browser refused: "+await errors);
                if(collectSummary is not null)await CommandAsync("assert-three-browser-checks");
                var receipt=application+"-auth-browser.json";
                File.Copy(Path.Combine(root,receipt),Path.Combine(output,receipt));
            }
            finally
            {
                if(!browser.HasExited)
                {
                    browser.Kill(entireProcessTree:true);
                    await browser.WaitForExitAsync();
                }
            }
        }
        internal async Task CollectOperationObservationAsync(string token)
        {
            var endpoint=Guid.Parse("30000000-0000-4000-8000-000000000078");
            var body=JsonSerializer.Serialize(new {schemaVersion=1,requestId=Guid.NewGuid(),targetKind="endpoint",
                targetId=endpoint,expectedTargetRevision=1,profileId="http-ready",expectedProfileVersion=1,tenantContext=(object?)null});
            using var request=new HttpRequestMessage(HttpMethod.Post,$"/resources/v1/endpoints/{endpoint:D}/checks")
            {
                Content=new StringContent(body,System.Text.Encoding.UTF8,"application/json")
            };
            request.Headers.Authorization=new("Bearer",token);
            using var response=await service!.SendAsync(request);
            Assert.Equal(HttpStatusCode.Accepted,response.StatusCode);
            using var accepted=JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var checkId=accepted.RootElement.GetProperty("checkId").GetGuid();
            for(var i=0;i<40;i++)
            {
                using var read=new HttpRequestMessage(HttpMethod.Get,$"/resources/v1/checks/{checkId:D}");
                read.Headers.Authorization=new("Bearer",token);
                using var current=await service.SendAsync(read);
                Assert.Equal(HttpStatusCode.OK,current.StatusCode);
                using var document=JsonDocument.Parse(await current.Content.ReadAsStringAsync());
                if(document.RootElement.GetProperty("state").GetString()=="completed")
                {
                    Assert.Equal("healthy",document.RootElement.GetProperty("health").GetString());
                    return;
                }
                await Task.Delay(250);
            }
            throw new InvalidOperationException("The registered Operation observation did not complete.");
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

internal class CloudControlServiceJointFactAttribute : FactAttribute
{
    public CloudControlServiceJointFactAttribute()
    {
        if(!OperatingSystem.IsLinux()||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"))
            ||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("FLEET_TEST_DATABASE"))
            ||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUD_CONTROL_SERVICE_FIXTURE_DIRECTORY")))
            Skip="Explicit isolated Auth/Service joint inputs are required; not validated by ordinary profiles.";
    }
}

internal class CloudControlConsoleBrowserJointFactAttribute : CloudControlServiceJointFactAttribute
{
    public CloudControlConsoleBrowserJointFactAttribute()
    {
        if(Skip is null && (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUD_CONTROL_CONSOLE_BROWSER_CHECKOUT"))
            ||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUD_CONTROL_CONSOLE_BROWSER_EVIDENCE"))))
            Skip="Explicit isolated Console browser inputs are required.";
    }
}

internal class CloudControlFleetBrowserJointFactAttribute : CloudControlConsoleBrowserJointFactAttribute
{
    public CloudControlFleetBrowserJointFactAttribute()
    {
        if(Skip is null && (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUD_CONTROL_FLEET_BROWSER_CHECKOUT"))
            ||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("FLEET_PLAYWRIGHT_MODULE"))))
            Skip="Explicit isolated Fleet browser inputs are required.";
    }
}

internal sealed class CloudControlOperationBrowserJointFactAttribute : CloudControlFleetBrowserJointFactAttribute
{
    public CloudControlOperationBrowserJointFactAttribute()
    {
        if(Skip is null && (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUD_CONTROL_OPERATION_BROWSER_CHECKOUT"))
            ||string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("OPERATION_PLAYWRIGHT_MODULE"))))
            Skip="Explicit isolated Operation browser inputs are required.";
    }
}
