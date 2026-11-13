using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class CloudControlProtocolTests
{
    [PostgresFact]
    public async Task Real_PKCE_encrypted_tokens_refresh_and_introspection_keep_each_existing_Web_profile_separate()
    {
        await using var fixture=await Fixture.CreateAsync();using var browser=fixture.Browser();
        foreach(var (client,allowed,denied) in new[]
        {
            (FirstPartyClients.CloudConsoleWeb,
                new[]{"cloud.resources.read","cloud.resources.manage","cloud.health.check","fleet.server.manage","fleet.platform.operate","fleet.approve"},
                new[]{"cloud.resources.summary.read","fleet.allocate","fleet.apply","fleet.retire","fleet.purge"}),
            (FirstPartyClients.FleetAdminWeb,new[]{"fleet.read","cloud.health.check"},
                new[]{"cloud.resources.read","cloud.resources.manage","cloud.resources.summary.read"}),
            (FirstPartyClients.CloudOperationWeb,new[]{"cloud.resources.summary.read"},
                new[]{"cloud.resources.read","cloud.resources.manage","cloud.health.check","fleet.read"})
        })
        {
            var token=await fixture.TokenAsync(browser,client,allowed);
            Assert.Equal(5,token.Access.Split('.').Length);
            var claims=await fixture.InspectAsync(browser,token.Access);
            AssertIdentity(claims,client,fixture.Subject,allowed);
            var time=claims.GetProperty("auth_time").GetInt64();
            using var response=await browser.PostAsync("/connect/token",new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["grant_type"]="refresh_token",["client_id"]=client,["client_secret"]="existing-fixture-secret",["refresh_token"]=token.Refresh
            }));
            Assert.Equal(HttpStatusCode.OK,response.StatusCode);
            using var refreshed=JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var current=await fixture.InspectAsync(browser,refreshed.RootElement.GetProperty("access_token").GetString()!);
            AssertIdentity(current,client,fixture.Subject,allowed);
            Assert.Equal(time,current.GetProperty("auth_time").GetInt64());
            foreach(var scope in denied)
            {
                using var refused=await browser.GetAsync(Fixture.AuthorizationRequest(client,[scope]));
                Assert.Equal(HttpStatusCode.BadRequest,refused.StatusCode);
                Assert.Null(refused.Headers.Location);
                Assert.Contains("invalid_request",await refused.Content.ReadAsStringAsync(),StringComparison.Ordinal);
            }
            using var machine=await browser.PostAsync("/connect/token",new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["grant_type"]="client_credentials",["client_id"]=client,["client_secret"]="existing-fixture-secret",["scope"]=allowed[0]
            }));
            Assert.Equal(HttpStatusCode.BadRequest,machine.StatusCode);
            Assert.Contains("unauthorized_client",await machine.Content.ReadAsStringAsync(),StringComparison.Ordinal);
        }
    }

    private static void AssertIdentity(JsonElement claims,string client,string subject,string[] allowed)
    {
        Assert.True(claims.GetProperty("active").GetBoolean());
        Assert.Equal("https://auth.appliket.com/",claims.GetProperty("iss").GetString());
        Assert.Equal(client,claims.GetProperty("client_id").GetString());
        Assert.Equal(subject,claims.GetProperty("sub").GetString());
        Assert.Equal("human",claims.GetProperty("subject_type").GetString());
        var audience=claims.GetProperty("aud");
        Assert.Equal(new[]{"fleet-api"},audience.ValueKind==JsonValueKind.Array
            ?audience.EnumerateArray().Select(value=>value.GetString()).ToArray():[audience.GetString()]);
        var scopes=claims.GetProperty("scope").GetString()!.Split(' ');
        Assert.Equal(new[]{"openid","profile","offline_access"}.Concat(allowed).Order(),scopes.Order());
        Assert.InRange(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-claims.GetProperty("auth_time").GetInt64(),0,120);
    }

    internal sealed class Fixture : IAsyncDisposable
    {
        private const string Password="Cloud-fixture-only!892";
        private const string Verifier="cloud-control-pkce-verifier-012345678901234567890123456789";
        private readonly AuthQualityPostgresFixture database;
        private readonly Factory factory;
        internal string Subject {get;}
        private Fixture(AuthQualityPostgresFixture database,string connection,string subject)
        {this.database=database;Subject=subject;factory=new(connection);}
        internal static async Task<Fixture> CreateAsync()
        {
            var database=await AuthQualityPostgresFixture.CreateAsync();
            try
            {
                await using var scope=database.Services.CreateAsyncScope();
                await CloudControlRegistrationTests.PrepareAsync(scope.ServiceProvider);
                var db=scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();var connection=db.Database.GetConnectionString()!;
                await CloudControlRegistration.ApplyOnlyAsync(scope.ServiceProvider,new AuthOptions
                    {Issuer="https://auth.appliket.com/",CloudControl=new(){Enabled=true}});
                var users=new ServiceCollection().AddLogging();users.AddSingleton(Options.Create(new AuthOptions()));
                users.AddDbContext<PandaAuthDbContext>(options=>options.UseNpgsql(connection).UseOpenIddict());users.AddUserStore();
                await using var userProvider=users.BuildServiceProvider();
                var user=new PandaUser {UserName="cloud-control-user",Email="cloud-control@example.test",EmailConfirmed=true};
                Assert.True((await userProvider.GetRequiredService<UserService>().CreateAsync(user,Password)).Succeeded);
                return new(database,connection,user.Id);
            }
            catch {await database.DisposeAsync();throw;}
        }
        internal HttpMessageHandler Transport()=>factory.Server.CreateHandler();
        internal async Task RevokeAsync(string client)
        {
            await using var scope=factory.Services.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<PandaAuth.Server.Features.Tokens.ITokenRevoker>()
                .RevokeUserTokensAsync(Subject,client);
        }
        internal HttpClient Browser()=>factory.CreateClient(new WebApplicationFactoryClientOptions
            {BaseAddress=new Uri("https://auth.appliket.com/"),AllowAutoRedirect=false,HandleCookies=true});
        private static string Callback(string client)=>"https://fixture.invalid/"+client+"/callback";
        internal static string AuthorizationRequest(string client,IEnumerable<string> scopes)=>
            "/connect/authorize?client_id="+client+"&redirect_uri="+Uri.EscapeDataString(Callback(client))+
            "&response_type=code&scope="+Uri.EscapeDataString("openid profile offline_access "+string.Join(' ',scopes))+
            "&state=cloud-control-state&nonce=cloud-control-nonce&code_challenge_method=S256&code_challenge="+
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));
        internal async Task<(string Access,string Refresh)> TokenAsync(HttpClient browser,string client,IEnumerable<string> scopes)
        {
            var authorize=AuthorizationRequest(client,scopes);
            using var redirect=await browser.GetAsync(authorize);
            Assert.Equal(HttpStatusCode.Redirect,redirect.StatusCode);
            var location=redirect.Headers.Location!;
            if(location.OriginalString.Contains("/account/login",StringComparison.OrdinalIgnoreCase))
            {
                using var page=await browser.GetAsync(location.IsAbsoluteUri?location.PathAndQuery:location.OriginalString);
                var hidden=Regex.Match(await page.Content.ReadAsStringAsync(),"name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
                Assert.True(hidden.Success);
                using var login=await browser.PostAsync("/account/login",new FormUrlEncodedContent(new Dictionary<string,string>
                {
                    ["__RequestVerificationToken"]=WebUtility.HtmlDecode(hidden.Groups[1].Value),
                    ["UserName"]="cloud-control-user",["Password"]=Password,["ReturnUrl"]=authorize
                }));
                Assert.Equal(HttpStatusCode.Redirect,login.StatusCode);
                using var authorized=await browser.GetAsync(authorize);Assert.Equal(HttpStatusCode.Redirect,authorized.StatusCode);
                location=authorized.Headers.Location!;
            }
            var query=QueryHelpers.ParseQuery(location.Query);Assert.Equal("cloud-control-state",query["state"].ToString());
            Assert.True(query.ContainsKey("code"));
            using var exchange=await browser.PostAsync("/connect/token",new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["client_id"]=client,["client_secret"]="existing-fixture-secret",["grant_type"]="authorization_code",
                ["code"]=query["code"].ToString(),["redirect_uri"]=Callback(client),["code_verifier"]=Verifier
            }));
            Assert.Equal(HttpStatusCode.OK,exchange.StatusCode);
            using var json=JsonDocument.Parse(await exchange.Content.ReadAsStringAsync());
            return (json.RootElement.GetProperty("access_token").GetString()!,json.RootElement.GetProperty("refresh_token").GetString()!);
        }
        internal async Task<JsonElement> InspectAsync(HttpClient browser,string token)
        {
            using var response=await browser.PostAsync("/connect/introspect",new FormUrlEncodedContent(new Dictionary<string,string>
                {["client_id"]="fleet-api",["client_secret"]="api-fixture-secret",["token"]=token}));
            Assert.Equal(HttpStatusCode.OK,response.StatusCode);using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.Clone();
        }
        public async ValueTask DisposeAsync(){await factory.DisposeAsync();await database.DisposeAsync();}
    }
    private sealed class Factory(string connection) : WebApplicationFactory<Program>
    {
        private readonly ProtocolHostContentRoot root=new(connection,new Dictionary<string,string>
        {
            ["Auth:Issuer"]="https://auth.appliket.com/",["Auth:HttpsRequired"]="false",["Auth:Seed:Enabled"]="false",
            ["Auth:CloudControl:Enabled"]="true"
        });
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");builder.UseContentRoot(root.Path);builder.ConfigureLogging(logging=>logging.ClearProviders());
            builder.ConfigureTestServices(services=>services.AddDataProtection().UseEphemeralDataProtectionProvider());
        }
        protected override void Dispose(bool disposing){base.Dispose(disposing);if(disposing)root.Dispose();}
    }
}
