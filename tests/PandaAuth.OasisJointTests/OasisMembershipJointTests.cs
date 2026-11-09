extern alias OasisOwner;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile.Oasis;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using oasis.api.ProfileAccess;
using oasis.application;
using oasis.application.Configuration;
using oasis.application.ProfileAccess;
using oasis.domain;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

// Opt-in owning-host test. Both real Programs and their real authorization/persistence paths run;
// only socket transport is replaced by TestServer, never membership or token issuance.
public sealed class OasisMembershipJointTests
{
    [Fact]
    public async Task Actual_auth_issuer_and_oasis_owner_bind_and_revoke_without_cached_permission()
    {
        Assert.False(string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES")),
            "An explicitly isolated PostgreSQL test endpoint is required.");
        const string issuer = "https://auth.fixture.test/";
        const string origin = "https://oasis.fixture.test/";
        const string callerClient = "auth-membership-joint";
        const string humanClient = "profile-joint-human";
        const string machineSecret = "fixture-machine-secret-00000000000000000000";
        const string resourceSecret = "fixture-resource-secret-0000000000000000000";
        var organization = Guid.NewGuid();
        var member = Guid.NewGuid();
        var directory = Directory.CreateTempSubdirectory("auth-oasis-joint-").FullName;
        var serviceFile = Path.Combine(directory, "service.secret");
        var resourceFile = Path.Combine(directory, "resource.secret");
        PrivateFile(serviceFile, machineSecret);
        PrivateFile(resourceFile, resourceSecret);
        WebApplicationFactory<OasisOwner::Program>? owner = null;
        SecurityProtocolFixture? auth = null;
        var capture = new CaptureValidatedProfile();
        var unavailable = false;
        var boundary = new List<string>();
        try
        {
            var settings = new Dictionary<string, string>
            {
                ["Auth:Issuer"] = issuer, ["Profile:Enabled"] = "true", ["Profile:AllowedClients:0"] = humanClient,
                ["Profile:Oasis:Enabled"] = "true", ["Profile:Oasis:Issuer"] = issuer,
                ["Profile:Oasis:Endpoint"] = origin.TrimEnd('/') + ProfileAccessContract.Route,
                ["Profile:Oasis:ClientId"] = callerClient, ["Profile:Oasis:ClientSecretFile"] = serviceFile,
                ["Profile:Oasis:OrganizationKeys:0"] = organization.ToString(),
            };
            auth = await SecurityProtocolFixture.CreateAsync(services =>
            {
                services.AddSingleton<IStartupFilter>(capture);
                services.AddHttpClient("oasis-profile-access").ConfigurePrimaryHttpMessageHandler(() => new Forward(async (request, ct) =>
                {
                    if (request.RequestUri!.GetLeftPart(UriPartial.Authority) == issuer.TrimEnd('/'))
                    {
                        using var sender = new HttpMessageInvoker(auth!.Host.Server.CreateHandler());
                        var result = await sender.SendAsync(request, ct);
                        boundary.Add("auth " + request.RequestUri.AbsolutePath + " " + (int)result.StatusCode);
                        return result;
                    }
                    Assert.Equal(origin.TrimEnd('/'), request.RequestUri.GetLeftPart(UriPartial.Authority));
                    if (unavailable) return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                    using var ownerSender = new HttpMessageInvoker(owner!.Server.CreateHandler());
                    var resultOwner = await ownerSender.SendAsync(request, ct);
                    boundary.Add("owner " + (int)resultOwner.StatusCode);
                    return resultOwner;
                }));
            }, settings);
            await auth.RegisterClientAsync(humanClient, ProfileScopes.Read, ProfileScopes.Resource);
            using (var scope = auth.Host.Services.CreateScope())
            {
                var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
                await scopes.CreateAsync(new OpenIddictScopeDescriptor { Name = ProfileAccessContract.Scope,
                    Resources = { ProfileAccessContract.Audience } });
                var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                await apps.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = callerClient, ClientSecret = machineSecret, ClientType = ClientTypes.Confidential,
                    Permissions = { Permissions.Endpoints.Token, Permissions.GrantTypes.ClientCredentials,
                        Permissions.Prefixes.Scope + ProfileAccessContract.Scope },
                });
                await apps.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = ProfileAccessContract.Audience, ClientSecret = resourceSecret, ClientType = ClientTypes.Confidential,
                    Permissions = { Permissions.Endpoints.Introspection },
                });
                var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                db.Users.Add(new PandaUser { Id = "joint-target" });
                await db.SaveChangesAsync();
            }
            var ownerSettings = new Dictionary<string, string?>
            {
                ["Oasis:Persistence:Sqlite:ConnectionString"] = "Data Source=" + Path.Combine(directory, "owner.db") + ";Pooling=False",
                ["Oasis:BackgroundJobs:Backup:Enabled"] = "false", ["Oasis:Seed:Enabled"] = "true",
                ["Oasis:Seed:SkipSampleData"] = "true", ["Oasis:Auth:BcryptWorkFactor"] = "4",
                [OasisOptions.AuthOptions.OidcIssuerKey] = issuer,
                [ProfileAccessOptions.SectionName + ":Enabled"] = "true",
                [ProfileAccessOptions.SectionName + ":Issuer"] = issuer,
                [ProfileAccessOptions.SectionName + ":ServiceOrigin"] = origin,
                [ProfileAccessOptions.SectionName + ":AllowedClientId"] = callerClient,
                [ProfileAccessOptions.SectionName + ":OrganizationKeys:0"] = organization.ToString(),
                [ProfileAccessOptions.SectionName + ":IntrospectionClientId"] = ProfileAccessContract.Audience,
                [ProfileAccessOptions.SectionName + ":IntrospectionSecretFile"] = resourceFile,
            };
            owner = new WebApplicationFactory<OasisOwner::Program>().WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureLogging(logging => logging.ClearProviders());
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    foreach (var source in config.Sources.OfType<JsonConfigurationSource>().ToArray()) config.Sources.Remove(source);
                    config.AddInMemoryCollection(ownerSettings);
                });
                builder.ConfigureServices(services =>
                {
                    services.AddProfileAccess(new ConfigurationBuilder().AddInMemoryCollection(ownerSettings).Build());
                    services.PostConfigureAll<HttpClientFactoryOptions>(options => options.HttpMessageHandlerBuilderActions.Add(builder =>
                        builder.PrimaryHandler = new Forward(async (request, ct) =>
                        {
                            Assert.Equal(issuer.TrimEnd('/'), request.RequestUri!.GetLeftPart(UriPartial.Authority));
                            using var sender = new HttpMessageInvoker(auth.Host.Server.CreateHandler());
                            return await sender.SendAsync(request, ct);
                        })));
                });
            });
            using (var scope = owner.Services.CreateScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<IUserRepository>();
                var requester = Guid.NewGuid(); var target = Guid.NewGuid();
                await users.AddAsync(new User(requester, "requester@example.invalid", "Requester", providerSubject: auth.UserId));
                await users.AddAsync(new User(target, "target@example.invalid", "Target", providerSubject: "joint-target"));
                var session = scope.ServiceProvider.GetRequiredService<IOasisDataSession>();
                await session.InsertAsync(new Tenant(organization, "Joint fixture", createdByUserId: requester));
                var members = scope.ServiceProvider.GetRequiredService<ITenantMemberRepository>();
                await members.AddAsync(new TenantMember(Guid.NewGuid(), organization, requester, null, null, MembershipStatus.Active));
                await members.AddAsync(new TenantMember(member, organization, target, null, null, MembershipStatus.Active));
            }
            // Warm only the fixture's discovery/introspection pipeline. A cold owner exceeding the
            // consumer's unchanged three-second budget correctly returned unavailable (499).
            // This is not a retry in production: the measured consumer call below starts separately.
            using (var protocol = auth.Host.CreateClient(new WebApplicationFactoryClientOptions
                { BaseAddress = new Uri(issuer), AllowAutoRedirect = false, HandleCookies = false }))
            {
                using var issued = await protocol.PostAsync(PandaAuthEndpoints.Token, new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = GrantTypes.ClientCredentials, ["client_id"] = callerClient,
                    ["client_secret"] = machineSecret, ["scope"] = ProfileAccessContract.Scope,
                }));
                Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
                using var issuedJson = JsonDocument.Parse(await issued.Content.ReadAsStringAsync());
                var serviceToken = issuedJson.RootElement.GetProperty("access_token").GetString()!;
                Assert.Equal(5, serviceToken.Split('.').Length);
                using var ownerClient = owner.CreateClient(new WebApplicationFactoryClientOptions
                    { BaseAddress = new Uri(origin), AllowAutoRedirect = false, HandleCookies = false });
                ownerClient.Timeout = TimeSpan.FromSeconds(30);
                using var request = new HttpRequestMessage(HttpMethod.Post, ProfileAccessContract.Route)
                {
                    Content = JsonContent.Create(new ProfileAccessRequest(Guid.NewGuid(), organization,
                        new ProfileAccount(issuer, auth.UserId), member, new[] { "avatar" })),
                };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", serviceToken);
                using var response = await ownerClient.SendAsync(request);
                Assert.True(response.StatusCode == HttpStatusCode.OK, "Owner warm-up status: " + (int)response.StatusCode);
            }
            using var browser = auth.Browser();
            browser.BaseAddress = new Uri(issuer);
            var token = await auth.IssueAsync(browser, humanClient, "openid " + ProfileScopes.Read);
            var bearer = token.GetProperty("access_token").GetString()!;
            Assert.Equal(5, bearer.Split('.').Length); // actual encrypted Auth access token
            browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            using var self = await browser.GetAsync(PandaAuthProfileApi.Self);
            Assert.Equal(HttpStatusCode.OK, self.StatusCode);
            Assert.NotNull(capture.Principal);
            await using var callScope = auth.Host.Services.CreateAsyncScope();
            var context = new DefaultHttpContext { User = capture.Principal!, RequestServices = callScope.ServiceProvider };
            var consumer = callScope.ServiceProvider.GetRequiredService<OasisProfileAccessClient>();
            var proof = await consumer.ResolveAsync(context, organization, member, new[] { "avatar" });
            Assert.True(proof is not null, "Boundaries: " + string.Join(", ", boundary) + "; issuerCount=" + context.User.GetClaims(Claims.Issuer).Length);
            Assert.NotNull(proof);
            Assert.Equal("joint-target", proof.TargetId);
            Assert.Null(await consumer.ResolveAsync(context, Guid.NewGuid(), member, new[] { "avatar" }));
            using (var scope = owner.Services.CreateScope())
            {
                var session = scope.ServiceProvider.GetRequiredService<IOasisDataSession>();
                await using var command = session.CreateCommand("UPDATE tenantmember SET status='disabled' WHERE id=@member");
                command.AddParameter("@member", member);
                await command.ExecuteNonQueryAsync();
            }
            Assert.Null(await consumer.ResolveAsync(context, organization, member, new[] { "avatar" }));
            unavailable = true;
            Assert.Null(await consumer.ResolveAsync(context, organization, member, new[] { "avatar" }));
        }
        finally
        {
            if (owner is not null) await owner.DisposeAsync();
            if (auth is not null) await auth.DisposeAsync();
            Directory.Delete(directory, true);
        }
    }

    private static void PrivateFile(string path, string value)
    {
        File.WriteAllText(path, value);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    private sealed class Forward(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct);
    }
    private sealed class CaptureValidatedProfile : IStartupFilter
    {
        internal ClaimsPrincipal? Principal;
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, forward) =>
            {
                await forward();
                if (context.Request.Path == PandaAuthProfileApi.Self && context.Response.StatusCode == 200)
                    Principal = new ClaimsPrincipal(context.User.Identities.Select(identity => new ClaimsIdentity(identity)));
            });
            next(app);
        };
    }
}
