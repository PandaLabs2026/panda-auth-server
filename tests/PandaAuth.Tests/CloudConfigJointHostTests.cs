using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Npgsql;
using PandaAuth.Shared;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.CloudConfig.JointFixture;
using Xunit;
namespace PandaAuth.Tests;
public sealed class CloudConfigJointHostTests
{
    [Theory]
    [InlineData(false,"")]
    [InlineData(true,"")]
    [InlineData(true,"{\"PgSocket\":\"/var/run/postgresql\",\"DoNotEcho\":\"DO_NOT_ECHO_FIXTURE_PAYLOAD\"}")]
    public async Task SeparateJointHostRefusesUnadmittedInputWithoutStartingOrEchoing(bool mode,string input)
    {
        var start=new ProcessStartInfo("dotnet"){RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
        foreach(var arg in new[]{"exec","--runtimeconfig",Path.Combine(AppContext.BaseDirectory,"PandaAuth.Tests.runtimeconfig.json"),"--depsfile",Path.Combine(AppContext.BaseDirectory,"PandaAuth.Tests.deps.json"),typeof(FixtureEntry).Assembly.Location})start.ArgumentList.Add(arg);
        if(mode)start.ArgumentList.Add("--fixture-stdin");
        using var process=Process.Start(start)!;var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();await process.StandardInput.WriteAsync(input);process.StandardInput.Close();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try{await process.WaitForExitAsync(timeout.Token);}catch{process.Kill(true);await process.WaitForExitAsync();throw;}
        Assert.Equal(78,process.ExitCode);Assert.Equal("",await output);Assert.Equal("AUTH_CONFIG_JOINT_NOT_ADMITTED",(await error).Trim());
    }
    [CloudConfigPostgresFact]
    public Task SeparateJointHostUsesRealUnixTlsLoginEncryptedTokenAndIntrospection()
        => RunRealJointHost("https://localhost/callback",false);
    [CloudConfigPostgresFact]
    public Task SeparateJointHostSupportsRealConsoleCallbackAndCloudAdminRole()
        => RunRealJointHost("https://localhost/callback/pandaauth",true);
    [CloudConfigPostgresFact]
    public Task SeparateJointHostSupportsFleetReadOnlyClientAndBothAudiences()
        => RunRealJointHost("https://localhost/callback",false,true);
    private static async Task RunRealJointHost(string callback,bool consoleRole,bool fleetRead=false)
    {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("Registered Linux fixture required.");
        var pg=new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_CONFIG_TEST_POSTGRES"));
        var root=Directory.CreateTempSubdirectory("auth-joint-").FullName;File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        using var rsa=RSA.Create(3072);var request=new CertificateRequest("CN=auth.appliket.com",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddDnsName("auth.appliket.com");request.CertificateExtensions.Add(san.Build());request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},true));using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        var password="Aa!9"+Convert.ToHexString(RandomNumberGenerator.GetBytes(20));var secret=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));var console=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var policy=new JointHostPolicy(root,pg.Host!,Environment.GetEnvironmentVariable("PANDA_AUTH_CONFIG_TEST_RUN")!,Convert.ToBase64String(certificate.Export(X509ContentType.Pkcs12)),password,secret,console);
        var start=new ProcessStartInfo("dotnet"){WorkingDirectory=root,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
        foreach(var arg in new[]{"exec","--runtimeconfig",Path.Combine(AppContext.BaseDirectory,"PandaAuth.Tests.runtimeconfig.json"),"--depsfile",Path.Combine(AppContext.BaseDirectory,"PandaAuth.Tests.deps.json"),typeof(FixtureEntry).Assembly.Location,"--fixture-stdin"})start.ArgumentList.Add(arg);
        using var process=Process.Start(start)!;var error=process.StandardError.ReadToEndAsync();
        try
        {
            var serialized=JsonSerializer.SerializeToNode(policy)!.AsObject();if(fleetRead)serialized["FleetReadEnabled"]=true;
            await process.StandardInput.WriteLineAsync(serialized.ToJsonString());await process.StandardInput.FlushAsync();
            var ready=await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(60));
            if(ready!="AUTH_CONFIG_JOINT_READY"){process.StandardInput.Close();await process.WaitForExitAsync();var diagnostic=Path.Combine(root,"failure.json");Assert.Fail(await error+(File.Exists(diagnostic)?await File.ReadAllTextAsync(diagnostic):""));}
            using var handler=new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=true,ConnectCallback=async(_,ct)=>{var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);try{await socket.ConnectAsync(new UnixDomainSocketEndPoint(Path.Combine(root,"auth.sock")),ct);return new NetworkStream(socket,true);}catch{socket.Dispose();throw;}},SslOptions=new SslClientAuthenticationOptions{RemoteCertificateValidationCallback=(_,cert,_,errors)=>cert is not null&&(errors&SslPolicyErrors.RemoteCertificateNameMismatch)==0&&cert.GetCertHashString(HashAlgorithmName.SHA256)==certificate.GetCertHashString(HashAlgorithmName.SHA256)}};
            using var browser=new HttpClient(handler){BaseAddress=new Uri(CloudConfigScopes.Issuer),Timeout=TimeSpan.FromSeconds(20)};
            using(var discovery=await browser.GetAsync(".well-known/openid-configuration")){Assert.Equal(HttpStatusCode.OK,discovery.StatusCode);using var json=JsonDocument.Parse(await discovery.Content.ReadAsStringAsync());Assert.Equal(CloudConfigScopes.Issuer,json.RootElement.GetProperty("issuer").GetString());}
            const string verifier="config-joint-pkce-verifier-012345678901234567890123456789";
            var clientId=fleetRead?FirstPartyClients.FleetAdminWeb:FirstPartyClients.CloudConsoleWeb;
            var requestedScopes=fleetRead?new[]{PandaAuthScopes.FleetRead,CloudConfigScopes.Read}:CloudConfigScopes.All;
            var authorize="/connect/authorize?client_id="+clientId+"&redirect_uri="+Uri.EscapeDataString(callback)+"&response_type=code&scope=openid%20profile%20"+(consoleRole?"roles%20":"")+string.Join("%20",requestedScopes)+"&state=joint-state&nonce=joint-nonce&code_challenge_method=S256&code_challenge="+Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
            using var redirect=await browser.GetAsync(authorize);Assert.Equal(HttpStatusCode.Redirect,redirect.StatusCode);using var page=await browser.GetAsync(redirect.Headers.Location!.PathAndQuery);var hidden=Regex.Match(await page.Content.ReadAsStringAsync(),"name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");Assert.True(hidden.Success);
            using var login=await browser.PostAsync("/account/login",new FormUrlEncodedContent(new Dictionary<string,string>{{"__RequestVerificationToken",WebUtility.HtmlDecode(hidden.Groups[1].Value)},{"UserName","config-joint-user"},{"Password",password},{"ReturnUrl",authorize}}));Assert.Equal(HttpStatusCode.Redirect,login.StatusCode);
            using var authorization=await browser.GetAsync(authorize);Assert.Equal(HttpStatusCode.Redirect,authorization.StatusCode);var query=Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorization.Headers.Location!.Query);Assert.Equal("joint-state",query["state"].ToString());
            using var exchange=await browser.PostAsync("/connect/token",new FormUrlEncodedContent(new Dictionary<string,string>{{"client_id",clientId},{"client_secret",console},{"grant_type","authorization_code"},{"code",query["code"].ToString()},{"redirect_uri",callback},{"code_verifier",verifier}}));Assert.Equal(HttpStatusCode.OK,exchange.StatusCode);using var token=JsonDocument.Parse(await exchange.Content.ReadAsStringAsync());var access=token.RootElement.GetProperty("access_token").GetString()!;Assert.Equal(5,access.Split('.').Length);
            using var inspected=await browser.PostAsync("/connect/introspect",new FormUrlEncodedContent(new Dictionary<string,string>{{"client_id",CloudConfigScopes.IntrospectionClient},{"client_secret",secret},{"token",access}}));Assert.Equal(HttpStatusCode.OK,inspected.StatusCode);using var claims=JsonDocument.Parse(await inspected.Content.ReadAsStringAsync());Assert.True(claims.RootElement.GetProperty("active").GetBoolean());Assert.Equal("human",claims.RootElement.GetProperty("subject_type").GetString());
            if(fleetRead)
            {
                Assert.Equal(new[]{PandaAuthScopes.FleetApi,CloudConfigScopes.Audience,CloudConfigScopes.IntrospectionClient}.Order(),claims.RootElement.GetProperty("aud").EnumerateArray().Select(value=>value.GetString()).Order());
                var granted=claims.RootElement.GetProperty("scope").GetString()!.Split(' ');
                Assert.Contains(PandaAuthScopes.FleetRead,granted);Assert.Contains(CloudConfigScopes.Read,granted);
                Assert.DoesNotContain(granted,scope=>scope.StartsWith("cloud.config.",StringComparison.Ordinal)&&scope!=CloudConfigScopes.Read);
                foreach(var scope in CloudConfigScopes.All.Where(scope=>scope!=CloudConfigScopes.Read))
                {
                    using var rejected=await browser.GetAsync(authorize.Replace("scope=openid%20profile%20"+string.Join("%20",requestedScopes),"scope=openid%20profile%20"+scope,StringComparison.Ordinal));
                    Assert.Equal(HttpStatusCode.BadRequest,rejected.StatusCode);
                }
            }
            if(consoleRole)
            {
                using var userinfoRequest=new HttpRequestMessage(HttpMethod.Get,PandaAuthEndpoints.Userinfo);
                userinfoRequest.Headers.Authorization=new("Bearer",access);
                using var userinfo=await browser.SendAsync(userinfoRequest);Assert.Equal(HttpStatusCode.OK,userinfo.StatusCode);
                using var profile=JsonDocument.Parse(await userinfo.Content.ReadAsStringAsync());
                var roles=profile.RootElement.GetProperty("role");
                Assert.True(roles.ValueKind==JsonValueKind.Array?roles.EnumerateArray().Any(role=>role.GetString()=="cloud-admin"):roles.GetString()=="cloud-admin");
            }
            process.StandardInput.Close();await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));Assert.Equal(0,process.ExitCode);Assert.Equal("",await error);
        }
        finally{if(!process.HasExited){process.Kill(true);await process.WaitForExitAsync();}Directory.Delete(root,true);}
    }

}
