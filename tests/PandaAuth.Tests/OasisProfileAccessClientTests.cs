using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Features.Profile.Oasis;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class OasisProfileAccessClientTests
{
    [Fact]
    public async Task Disabled_consumer_is_registered_and_never_contacts_external_services()
    {
        await using var fixture = new Fixture(enabled: false);
        Assert.Null(await fixture.Resolve());
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task Trusted_actor_receives_only_bound_internal_capability_and_every_read_is_fresh()
    {
        await using var fixture = new Fixture();
        var proof = await fixture.Resolve();
        Assert.NotNull(proof);
        Assert.Equal(fixture.Organization, proof.OrganizationKey);
        Assert.Equal(fixture.Member, proof.MemberKey);
        Assert.Equal("requester", proof.RequesterId);
        Assert.Equal("target", proof.TargetId);
        Assert.Equal(new[] { "avatar" }, proof.AllowedFields);
        var previous = fixture.Transport.LastRequestId;
        fixture.Transport.Mode = "unavailable";
        Assert.Null(await fixture.Resolve());
        Assert.NotEqual(previous, fixture.Transport.LastRequestId);
        Assert.Equal(4, fixture.Transport.Calls); // no cached token or authorization fallback
        var db = fixture.Scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var audit = await db.SecurityEvents.ToListAsync();
        Assert.Contains(audit, e => e.EventType == "profile.membership.resolve");
        Assert.DoesNotContain(audit, e => (e.Metadata ?? "").Contains("fixture-service-secret", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("expiresType")]
    [InlineData("scope")]
    [InlineData("type")]
    [InlineData("duplicate")]
    [InlineData("unknown")]
    [InlineData("redirect")]
    [InlineData("oversize")]
    public async Task Invalid_token_endpoint_output_never_reaches_owner(string mode)
    {
        await using var fixture = new Fixture();
        fixture.Transport.TokenMode = mode;
        Assert.Null(await fixture.Resolve());
        Assert.Equal(1, fixture.Transport.Calls);
    }

    [Theory]
    [InlineData("requestId")]
    [InlineData("organizationKey")]
    [InlineData("targetMemberKey")]
    [InlineData("issuer")]
    [InlineData("unknownAccount")]
    [InlineData("disabledAccount")]
    [InlineData("emptyFields")]
    [InlineData("expandedFields")]
    [InlineData("duplicateFields")]
    [InlineData("duplicateProperty")]
    [InlineData("unknownProperty")]
    [InlineData("invalidJson")]
    [InlineData("invalidUtf8")]
    [InlineData("tooLarge")]
    [InlineData("redirect")]
    [InlineData("unavailable")]
    [InlineData("cacheable")]
    [InlineData("encoded")]
    [InlineData("mediaType")]
    public async Task Untrusted_owner_response_never_grants_a_capability(string mode)
    {
        await using var fixture = new Fixture();
        fixture.Transport.Mode = mode;
        Assert.Null(await fixture.Resolve());
    }

    [Theory]
    [InlineData("machine")]
    [InlineData("issuer")]
    [InlineData("presenter")]
    [InlineData("scope")]
    [InlineData("subject")]
    [InlineData("disabled")]
    [InlineData("organization")]
    [InlineData("fields")]
    [InlineData("member")]
    public async Task Untrusted_caller_or_selector_is_rejected_before_external_calls(string mode)
    {
        await using var fixture = new Fixture();
        var identity = (ClaimsIdentity)fixture.Caller.User.Identity!;
        switch (mode)
        {
            case "machine": identity.SetClaim(PandaAuthClaims.SubjectType, "machine"); break;
            case "issuer": identity.SetClaim("iss", "https://other.example.test/"); break;
            case "presenter": identity.SetPresenters("other-client"); break;
            case "scope": identity.SetScopes("openid"); break;
            case "subject": identity.AddClaim(new Claim("sub", "forged")); break;
            case "disabled":
                var db = fixture.Scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                (await db.Users.SingleAsync(u => u.Id == "requester")).Status = UserStatus.Frozen;
                await db.SaveChangesAsync();
                break;
        }
        Assert.Null(await fixture.Client.ResolveAsync(fixture.Caller,
            mode == "organization" ? Guid.NewGuid() : fixture.Organization,
            mode == "member" ? Guid.Empty : fixture.Member,
            mode == "fields" ? new[] { "roles" } : new[] { "avatar" }));
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("http")]
    [InlineData("path")]
    [InlineData("query")]
    [InlineData("client")]
    [InlineData("organizations")]
    [InlineData("secret")]
    public void Enabled_invalid_registration_is_rejected(string mode)
    {
        using var fixture = new Fixture(initialize: false);
        var configuration = fixture.Configuration();
        switch (mode)
        {
            case "issuer": configuration["Profile:Oasis:Issuer"] = "https://other.example.test/"; break;
            case "http": configuration["Profile:Oasis:Endpoint"] = "http://oasis.example.test/api/integrations/panda-auth/v1/profile-access"; break;
            case "path": configuration["Profile:Oasis:Endpoint"] = "https://oasis.example.test/other"; break;
            case "query": configuration["Profile:Oasis:Endpoint"] += "?override=true"; break;
            case "client": configuration["Profile:Oasis:ClientId"] = "oasis-profile-access-api"; break;
            case "organizations": configuration["Profile:Oasis:OrganizationKeys:0"] = Guid.Empty.ToString(); break;
            case "secret": configuration["Profile:Oasis:ClientSecretFile"] += ".absent"; break;
        }
        var error = Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddSelfProfiles(configuration));
        Assert.Equal("Oasis profile registration is invalid.", error.Message);
    }

    [Fact]
    public async Task Token_and_owner_share_one_deadline_and_caller_cancellation_propagates()
    {
        await using var fixture = new Fixture();
        fixture.Transport.Delay = TimeSpan.FromMilliseconds(1700);
        var watch = Stopwatch.StartNew();
        Assert.Null(await fixture.Resolve());
        Assert.InRange(watch.Elapsed, TimeSpan.FromSeconds(2.5), TimeSpan.FromSeconds(5));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Client.ResolveAsync(
            fixture.Caller, fixture.Organization, fixture.Member, new[] { "avatar" }, cancellation.Token));
    }

    internal sealed class Fixture : IDisposable, IAsyncDisposable
    {
        internal const string Issuer = "https://auth.example.test/";
        internal readonly Guid Organization = Guid.NewGuid();
        internal readonly Guid Member = Guid.NewGuid();
        internal readonly Transport Transport = new();
        internal readonly string SecretPath;
        private ServiceProvider? provider;
        internal AsyncServiceScope Scope;
        internal DefaultHttpContext Caller = new();
        internal OasisProfileAccessClient Client => Scope.ServiceProvider.GetRequiredService<OasisProfileAccessClient>();

        internal Fixture(bool enabled = true, bool initialize = true)
        {
            SecretPath = Path.Combine(Path.GetTempPath(), "oasis-secret-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(SecretPath, "fixture-service-secret-00000000000000000000");
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(SecretPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            if (!initialize) return;
            var configuration = Configuration(enabled);
            var services = new ServiceCollection().AddLogging();
            services.Configure<AuthOptions>(configuration.GetSection("Auth"));
            services.AddDbContext<PandaAuthDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
            services.AddSingleton(TimeProvider.System);
            services.AddScoped<SecurityEventWriter>();
            services.AddSelfProfiles(configuration);
            services.AddHttpClient("oasis-profile-access").ConfigurePrimaryHttpMessageHandler(() => Transport);
            provider = services.BuildServiceProvider();
            Scope = provider.CreateAsyncScope();
            var db = Scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            db.Users.AddRange(new PandaUser { Id = "requester" }, new PandaUser { Id = "target" },
                new PandaUser { Id = "disabled", Status = UserStatus.Frozen });
            db.SaveChanges();
            var identity = new ClaimsIdentity("Bearer");
            identity.SetClaim("sub", "requester").SetClaim("iss", Issuer)
                .SetClaim(PandaAuthClaims.SubjectType, PandaAuthClaims.SubjectTypes.Human);
            identity.SetScopes(ProfileScopes.Read).SetAudiences(ProfileScopes.Resource).SetPresenters("consumer-test");
            Caller.User = new ClaimsPrincipal(identity);
            Caller.RequestServices = Scope.ServiceProvider;
        }

        internal IConfigurationRoot Configuration(bool enabled = true) => new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:Issuer"] = Issuer, ["Profile:Enabled"] = "true", ["Profile:AllowedClients:0"] = "consumer-test",
                ["Profile:Oasis:Enabled"] = enabled.ToString(), ["Profile:Oasis:Issuer"] = Issuer,
                ["Profile:Oasis:Endpoint"] = "https://oasis.example.test/api/integrations/panda-auth/v1/profile-access",
                ["Profile:Oasis:ClientId"] = "auth-membership-client", ["Profile:Oasis:ClientSecretFile"] = SecretPath,
                ["Profile:Oasis:OrganizationKeys:0"] = Organization.ToString(),
            }).Build();
        internal Task<OasisMembershipProof?> Resolve() => Client.ResolveAsync(Caller, Organization, Member, new[] { "avatar" });
        public void Dispose() { if (provider is not null) { Scope.Dispose(); provider.Dispose(); } File.Delete(SecretPath); }
        public async ValueTask DisposeAsync() { if (provider is not null) { await Scope.DisposeAsync(); await provider.DisposeAsync(); } File.Delete(SecretPath); }
    }

    internal sealed class Transport : HttpMessageHandler
    {
        internal int Calls;
        internal string Mode = "";
        internal string TokenMode = "";
        internal TimeSpan Delay;
        internal string? LastRequestId;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, cancellationToken);
            if (request.RequestUri!.AbsolutePath == "/connect/token")
            {
                Assert.Equal("https://auth.example.test/connect/token", request.RequestUri.ToString());
                var form = await request.Content!.ReadAsStringAsync(cancellationToken);
                Assert.Contains("scope=profile.membership.resolve", form);
                Assert.Contains("grant_type=client_credentials", form);
                Assert.Contains("client_id=auth-membership-client", form);
                Assert.DoesNotContain("profile.read", form);
                var tokenJson = "{\"access_token\":\"fixture-encrypted-access-token\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"profile.membership.resolve\"}";
                tokenJson = TokenMode switch
                {
                    "expiresType" => tokenJson.Replace("\"expires_in\":60", "\"expires_in\":\"60\"", StringComparison.Ordinal),
                    "scope" => tokenJson.Replace("profile.membership.resolve", "profile.read", StringComparison.Ordinal),
                    "type" => tokenJson.Replace("Bearer", "Basic", StringComparison.Ordinal),
                    "duplicate" => tokenJson[..^1] + ",\"access_token\":\"different\"}",
                    "unknown" => tokenJson[..^1] + ",\"identity\":\"forged\"}",
                    "oversize" => tokenJson + new string(' ', 16385),
                    _ => tokenJson,
                };
                var tokenResponse = Json(tokenJson);
                if (TokenMode == "redirect") tokenResponse.StatusCode = HttpStatusCode.TemporaryRedirect;
                return tokenResponse;
            }
            Assert.Equal("https://oasis.example.test/api/integrations/panda-auth/v1/profile-access", request.RequestUri.ToString());
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal("fixture-encrypted-access-token", request.Headers.Authorization?.Parameter);
            var input = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!;
            Assert.Equal("requester", input["requester"]!["subject"]!.GetValue<string>());
            Assert.Equal(Fixture.Issuer, input["requester"]!["issuer"]!.GetValue<string>());
            LastRequestId = input["requestId"]!.GetValue<string>();
            var output = new JsonObject
            {
                ["requestId"] = LastRequestId, ["organizationKey"] = input["organizationKey"]!.GetValue<string>(),
                ["targetMemberKey"] = input["targetMemberKey"]!.GetValue<string>(),
                ["target"] = new JsonObject { ["issuer"] = Fixture.Issuer, ["subject"] = "target" },
                ["allowedFields"] = new JsonArray("avatar"),
            };
            switch (Mode)
            {
                case "requestId": case "organizationKey": case "targetMemberKey": output[Mode] = Guid.NewGuid().ToString(); break;
                case "issuer": output["target"]!["issuer"] = "https://other.example.test/"; break;
                case "unknownAccount": output["target"]!["subject"] = "missing"; break;
                case "disabledAccount": output["target"]!["subject"] = "disabled"; break;
                case "emptyFields": output["allowedFields"] = new JsonArray(); break;
                case "expandedFields": output["allowedFields"] = new JsonArray("avatar", "contactEmail"); break;
                case "duplicateFields": output["allowedFields"] = new JsonArray("avatar", "avatar"); break;
                case "unknownProperty": output["roles"] = "admin"; break;
            }
            var json = output.ToJsonString();
            if (Mode == "duplicateProperty") json = json[..^1] + ",\"requestId\":\"" + LastRequestId + "\"}";
            if (Mode == "invalidJson") json = "{";
            if (Mode == "tooLarge") json += new string(' ', 8193);
            var response = Json(json);
            switch (Mode)
            {
                case "invalidUtf8": response.Content = new ByteArrayContent(new byte[] { 0xC0, 0xAF }); response.Content.Headers.ContentType = new("application/json"); break;
                case "redirect": response.StatusCode = HttpStatusCode.TemporaryRedirect; response.Headers.Location = new Uri("https://other.example.test/"); break;
                case "unavailable": response.StatusCode = HttpStatusCode.ServiceUnavailable; break;
                case "cacheable": response.Headers.CacheControl = null; break;
                case "encoded": response.Content.Headers.ContentEncoding.Add("gzip"); break;
                case "mediaType": response.Content.Headers.ContentType = new("text/plain"); break;
            }
            return response;
        }
        private static HttpResponseMessage Json(string value)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
            response.Headers.CacheControl = new() { NoStore = true };
            return response;
        }
    }
}
