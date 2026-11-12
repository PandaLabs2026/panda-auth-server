extern alias OasisHost;
extern alias OasisFixtures;

using System.Net;
using System.Diagnostics;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Features.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Playwright;
using OpenIddict.Abstractions;
using oasis.api;
using oasis.api.Identity;
using oasis.application.Identity;
using OpenIddict.Client;
using oasis.application;
using oasis.domain;
using oasis.infrastructure;
using PandaAuth.Bff;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

// Explicit -p:OasisIdentityJoint=true lane. Both real Programs, two owned PG servers,
// real code+PKCE/TOTP/RT rotation, real Chromium. Proxies only bridge TestServer to HTTPS.
public sealed class OasisIdentityJointTests
{
    [Fact]
    public async Task Browser_code_flow_rotation_revocation_and_unknown_response_keep_instance_boundaries()
    {
        Assert.Equal("1", Environment.GetEnvironmentVariable("OASIS_PG_TESTS"));
        using var certificate = Certificate();
        await using var authProxy = await HttpsProxy.StartAsync(certificate);
        await using var oasisProxy = await HttpsProxy.StartAsync(certificate);
        var issuer = authProxy.Origin + "/";
        await using var auth = await SecurityProtocolFixture.CreateAsync(settings: new Dictionary<string, string>
        { ["Auth:Issuer"] = issuer, ["Auth:RateLimit:IpPerMinute"] = "100", ["Auth:RateLimit:AccountPerMinute"] = "100",
          ["Auth:RateLimit:MfaChallengeIpPerMinute"] = "100", ["Auth:RateLimit:MfaChallengeAccountPerMinute"] = "100" });
        authProxy.Client = new HttpClient(auth.Host.Server.CreateHandler());
        await auth.RegisterClientAsync(FirstPartyClients.OasisWeb);
        await auth.EnableTotpAsync();
        var otherPassword = "Aa!9" + Guid.NewGuid().ToString("N");
        string otherAuthId;
        var collisionPassword = "Aa!9" + Guid.NewGuid().ToString("N");
        using (var scope = auth.Host.Services.CreateScope())
        {
            var account = new PandaUser { UserName = "joint-other", Email = "joint-other@example.test", EmailConfirmed = true };
            Assert.True((await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(account, otherPassword)).Succeeded);
            otherAuthId = account.Id;
            var collision = new PandaUser { UserName = "joint-collision", Email = "joint@example.test", EmailConfirmed = true };
            Assert.True((await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(collision, collisionPassword)).Succeeded);
        }
        using (var scope = auth.Host.Services.CreateScope())
        {
            var clients = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var client = (await clients.FindByClientIdAsync(FirstPartyClients.OasisWeb))!;
            var descriptor = new OpenIddictApplicationDescriptor();
            await clients.PopulateAsync(descriptor, client);
            descriptor.RedirectUris.Add(new Uri(oasisProxy.Origin + "/signin-oidc"));
            await clients.UpdateAsync(client, descriptor);
        }
        await using var database = new OasisFixtures::oasis.tests.PgTestSupport.PgDatabaseFixture();
        await database.CreateDatabaseAsync();
        var settings = new Dictionary<string, string?>
        {
            ["Oasis:Persistence:Provider"] = "Npgsql", ["Oasis:Persistence:Npgsql:ConnectionString"] = database.ConnectionString,
            ["Oasis:Auth:Oidc:Issuer"] = issuer, ["Oasis:Auth:Oidc:ClientId"] = FirstPartyClients.OasisWeb,
            ["Oasis:Auth:Oidc:ClientSecret"] = SecurityProtocolFixture.Secret, ["OASIS_DEPLOYMENT_MODE"] = "Single",
            ["Oasis:RateLimit:Auth:PermitLimit"] = "100", ["Oasis:BackgroundJobs:Backup:Enabled"] = "false", ["Oasis:Seed:Enabled"] = "false",
            ["Oasis:IdentityBinding:Enabled"] = "true", ["Oasis:IdentityBinding:Issuer"] = issuer,
            ["Oasis:IdentityBinding:PlatformTenantId"] = "t0000", ["Oasis:IdentityBinding:InstanceId"] = "owned-joint-fixture",
            ["Oasis:IdentityBinding:PublicOrigin"] = oasisProxy.Origin
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var seed = new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config);
        seed.AddOasisInfrastructure(config);
        Guid userId = Guid.NewGuid(), tenantId, memberId = Guid.NewGuid();
        await using (var services = seed.BuildServiceProvider())
        {
            await services.GetRequiredService<IDatabaseInitializer>().InitializeAsync();
            await services.GetRequiredService<IUserRepository>().AddAsync(new User(userId, "joint@example.test", "Joint member",
                providerSubject: auth.UserId, providerIssuer: issuer));
            tenantId = (await services.GetRequiredService<ITenantStore>().CreateDefaultAsync("Owned joint workspace", userId)).Id;
            await services.GetRequiredService<ITenantMemberRepository>().AddAsync(new TenantMember(memberId, tenantId, userId, null, "[\"tenantadmin\"]", MembershipStatus.Active));
        }
        settings["Oasis:IdentityBinding:WorkspaceTenantId"] = tenantId.ToString();
        var backchannel = new AuthBackchannel(auth);
        await using var oasis = new WebApplicationFactory<OasisHost::Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development").ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(settings));
            builder.ConfigureServices(services =>
            {
                services.AddOasisOidcAuth(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
                services.AddSingleton<IHttpClientFactory>(backchannel);
                services.AddSingleton<IOasisTokenRefresher>(provider => new PreparedRefresher(
                    new OpenIddictOasisTokenRefresher(provider.GetRequiredService<OpenIddictClientService>(), provider.GetRequiredService<InstanceIdentityBindingOptions>()), backchannel));
            });
        });
        oasisProxy.Client = new HttpClient(oasis.Server.CreateHandler());
        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true, ExecutablePath = Environment.GetEnvironmentVariable("PANDALABS_TEST_CHROMIUM") });
        await using var context = await browser.NewContextAsync(new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        var page = await context.NewPageAsync();
        var authCookieName = auth.Host.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(LoginSessionService.Scheme).Cookie.Name!;
        async Task Login(IPage? targetPage = null, IBrowserContext? targetContext = null, string username = "security-admin", string? password = null, bool mfa = true, string landing = "/console")
        {
            var loginPage = targetPage ?? page;
            var loginContext = targetContext ?? context;
            if (mfa)
            {
                await using var db = auth.Context();
                await db.TotpFactors.Where(f => f.UserId == auth.UserId).ExecuteUpdateAsync(update => update.SetProperty(f => f.LastAcceptedTimeStep, (long?)null));
            }
            // Fresh Auth cookie avoids depending on an already-authenticated form branch.
            await loginContext.ClearCookiesAsync(new BrowserContextClearCookiesOptions { Name = authCookieName });
            var loginEntry = await loginPage.GotoAsync(oasisProxy.Origin + "/api/v1/auth/oidc/challenge");
            Assert.Equal(200, loginEntry!.Status);
            await loginPage.Locator("input[name='UserName']").FillAsync(username);
            await loginPage.Locator("input[name='Password']").FillAsync(password ?? auth.AdminPassword);
            await loginPage.Locator("button[type='submit']").First.ClickAsync();
            if (mfa)
            {
                await loginPage.Locator("input[name='Code']").FillAsync(auth.CurrentTotpCode());
                await loginPage.Locator("button[type='submit']").First.ClickAsync();
            }
            await loginPage.WaitForURLAsync(oasisProxy.Origin + landing);
        }
        await Login();
        async Task<int> Check()
        {
            await using var response = await context.APIRequest.GetAsync(oasisProxy.Origin + "/api/v1/auth/me");
            return response.Status;
        }
        Assert.Equal(200, await Check());
        var cookie = (await context.CookiesAsync(oasisProxy.Origin)).Single(c => c.Name == "__Host-Oasis.Auth");
        Assert.True(cookie.Secure && cookie.HttpOnly);
        Assert.Equal(SameSiteAttribute.Strict, cookie.SameSite);
        Assert.DoesNotContain("access_token", cookie.Value);
        Assert.True(cookie.Value.Length < 2048);
        var options = oasis.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(OasisCookieAuthentication.Scheme);
        var reference = options.TicketDataFormat.Unprotect(cookie.Value)!;
        var sessionId = reference.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
        var tickets = oasis.Services.GetRequiredService<PandaAuthBffVersionedTicketStore>();
        async Task<string> ExpireAccessToken()
        {
            var ticket = (await tickets.RetrieveAsync(sessionId))!;
            var refresh = Microsoft.AspNetCore.Authentication.AuthenticationTokenExtensions.GetTokenValue(ticket.Properties, "refresh_token")!;
            var tokens = Microsoft.AspNetCore.Authentication.AuthenticationTokenExtensions.GetTokens(ticket.Properties).ToList();
            tokens.Single(t => t.Name == "expires_at").Value = DateTimeOffset.UtcNow.AddSeconds(-1).ToString("O");
            Microsoft.AspNetCore.Authentication.AuthenticationTokenExtensions.StoreTokens(ticket.Properties, tokens);
            Assert.True(await tickets.TryRenewAsync(sessionId, ticket));
            return refresh;
        }
        var siblingPage = await context.NewPageAsync();
        await siblingPage.GotoAsync(oasisProxy.Origin + "/");
        var oldRefresh = await ExpireAccessToken();
        const string concurrentChecks = "async () => Promise.all(Array.from({length:4}, async () => (await fetch('/api/v1/auth/me')).status))";
        var checks = await Task.WhenAll(page.EvaluateAsync<int[]>(concurrentChecks), siblingPage.EvaluateAsync<int[]>(concurrentChecks));
        Assert.All(checks.SelectMany(statuses => statuses), status => Assert.Equal(200, status));
        Assert.Equal(1, backchannel.RefreshRequests);
        Assert.NotEqual(oldRefresh, Microsoft.AspNetCore.Authentication.AuthenticationTokenExtensions.GetTokenValue((await tickets.RetrieveAsync(sessionId))!.Properties, "refresh_token"));
        await siblingPage.CloseAsync();

        // A second real Auth identity is mirrored without an implicit membership.
        await using var otherContext = await browser.NewContextAsync(new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        var otherPage = await otherContext.NewPageAsync();
        await Login(otherPage, otherContext, "joint-other", otherPassword, false);
        Assert.Equal("Workspace access required", await otherPage.Locator("h1").TextContentAsync());
        var blockedDirective = await otherPage.EvaluateAsync<string>("""
            () => new Promise(resolve => {
              addEventListener('securitypolicyviolation', event => resolve(event.effectiveDirective), {once:true});
              fetch('/api/v1/auth/me').catch(() => {});
              setTimeout(() => resolve('no policy event'), 2000);
            })
            """);
        Assert.Equal("connect-src", blockedDirective);
        async Task<int> OtherCheck()
        {
            await using var response = await otherContext.APIRequest.GetAsync(oasisProxy.Origin + "/api/v1/auth/me");
            return response.Status;
        }
        Assert.Equal(403, await OtherCheck());
        var otherUser = (await oasis.Services.GetRequiredService<IUserRepository>().GetByExternalIdentityAsync(new oasis.application.Identity.ExternalIdentityKey(issuer, otherAuthId)))!;
        Assert.NotEqual(userId, otherUser.Id);
        async Task<int> AdminPost(string path, object? body = null) => await page.EvaluateAsync<int>("""
            async arg => { const token = document.cookie.match(/(?:^|;\s*)\.Oasis\.CSRF\.Token=([^;]*)/);
              return (await fetch(arg.path, {method:'POST', redirect:'manual', headers:{'Content-Type':'application/json','X-CSRF-TOKEN':decodeURIComponent(token?.[1] || '')}, body:JSON.stringify(arg.body || {})})).status; }
            """, new { path, body });
        Assert.Equal(200, await AdminPost("/api/v1/tenants/" + tenantId + "/members", new { userId = otherUser.Id, email = "display-only@example.test" }));
        Assert.Equal(200, await OtherCheck());
        await using (var deniedAdmin = await otherContext.APIRequest.GetAsync(oasisProxy.Origin + "/api/v1/admin/users"))
            Assert.Equal(403, deniedAdmin.Status);
        Assert.Equal(200, await AdminPost("/api/v1/tenants/" + tenantId + "/members/" + otherUser.Id + "/disable"));
        Assert.Equal(403, await OtherCheck());
        await Login(otherPage, otherContext, "joint-other", otherPassword, false);
        Assert.Equal(403, await OtherCheck());

        await using var collisionContext = await browser.NewContextAsync(new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        var collisionPage = await collisionContext.NewPageAsync();
        await Login(collisionPage, collisionContext, "joint-collision", collisionPassword, false, "/identity-review");
        Assert.Equal("Identity review required", await collisionPage.Locator("h1").TextContentAsync());
        await using (var collisionMe = await collisionContext.APIRequest.GetAsync(oasisProxy.Origin + "/api/v1/auth/me"))
            Assert.Equal(401, collisionMe.Status);
        Assert.Equal(userId, (await oasis.Services.GetRequiredService<IUserRepository>().GetByEmailAsync("joint@example.test"))!.Id);

        var members = oasis.Services.GetRequiredService<ITenantMemberRepository>();
        await members.UpdateAsync(new TenantMember(memberId, tenantId, userId, null, "[\"tenantadmin\"]", MembershipStatus.Disabled));
        Assert.Equal(403, await Check());
        var previousSession = sessionId;
        await Login();
        Assert.Equal(403, await Check());
        Assert.Null(await tickets.RetrieveAsync(previousSession));
        cookie = (await context.CookiesAsync(oasisProxy.Origin)).Single(c => c.Name == "__Host-Oasis.Auth");
        sessionId = options.TicketDataFormat.Unprotect(cookie.Value)!.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
        await members.UpdateAsync(new TenantMember(memberId, tenantId, userId, null, "[\"tenantadmin\"]", MembershipStatus.Active));
        backchannel.UserinfoUnavailable = true;
        Assert.Equal(503, await Check());
        Assert.NotNull(await tickets.RetrieveAsync(sessionId));
        backchannel.UserinfoUnavailable = false;
        Assert.Equal(200, await Check());

        backchannel.SlowUserinfo = true;
        var elapsed = Stopwatch.StartNew();
        Assert.Equal(503, await Check());
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(6));
        Assert.NotNull(await tickets.RetrieveAsync(sessionId));
        backchannel.SlowUserinfo = false;
        Assert.Equal(200, await Check());
        await using (var db = auth.Context())
        {
            var account = await db.Users.SingleAsync(u => u.Id == auth.UserId);
            account.SecurityStamp = Guid.NewGuid().ToString();
            await db.SaveChangesAsync();
        }
        Assert.Equal(401, await Check());
        Assert.Null(await tickets.RetrieveAsync(sessionId));
        await Login();
        Assert.Equal(200, await Check());
        cookie = (await context.CookiesAsync(oasisProxy.Origin)).Single(c => c.Name == "__Host-Oasis.Auth");
        sessionId = options.TicketDataFormat.Unprotect(cookie.Value)!.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
        var retryableRefresh = await ExpireAccessToken();
        backchannel.PrepareUnavailable = true;
        Assert.Equal(503, await Check());
        Assert.Equal(retryableRefresh, Microsoft.AspNetCore.Authentication.AuthenticationTokenExtensions.GetTokenValue((await tickets.RetrieveAsync(sessionId))!.Properties, "refresh_token"));
        backchannel.PrepareUnavailable = false;
        Assert.Equal(200, await Check());
        await ExpireAccessToken();
        backchannel.TemporaryRefreshFailure = true;
        var sendsBeforeAmbiguous = backchannel.RefreshRequests;
        Assert.Equal(503, await Check());
        backchannel.TemporaryRefreshFailure = false;
        Assert.Equal(503, await Check());
        Assert.Equal(sendsBeforeAmbiguous + 1, backchannel.RefreshRequests);
        await Login();
        cookie = (await context.CookiesAsync(oasisProxy.Origin)).Single(c => c.Name == "__Host-Oasis.Auth");
        sessionId = options.TicketDataFormat.Unprotect(cookie.Value)!.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
        await ExpireAccessToken();
        using (var scope = auth.Host.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeUserTokensAsync(auth.UserId);
        Assert.Equal(401, await Check());
        Assert.Null(await tickets.RetrieveAsync(sessionId));
        await Login();
        cookie = (await context.CookiesAsync(oasisProxy.Origin)).Single(c => c.Name == "__Host-Oasis.Auth");
        sessionId = options.TicketDataFormat.Unprotect(cookie.Value)!.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;

        var requestsBeforeUnknown = backchannel.RefreshRequests;
        await ExpireAccessToken();
        backchannel.LoseRefreshResponse = true;
        Assert.Equal(503, await Check());
        Assert.Equal(requestsBeforeUnknown + 1, backchannel.RefreshRequests);
        Assert.Equal(503, await Check());
        Assert.Equal(requestsBeforeUnknown + 1, backchannel.RefreshRequests); // No protocol or browser retry of the old RT.
        var logoutStatus = await AdminPost("/api/v1/auth/logout");
        Assert.True(logoutStatus is 0 or 200 or 302); // fetch may follow the RP logout redirect.
        Assert.Null(await tickets.RetrieveAsync(sessionId));
        Assert.Equal(401, await Check());
        backchannel.LoseRefreshResponse = false;
        await Login();
        cookie = (await context.CookiesAsync(oasisProxy.Origin)).Single(c => c.Name == "__Host-Oasis.Auth");
        sessionId = options.TicketDataFormat.Unprotect(cookie.Value)!.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
        await ExpireAccessToken();
        backchannel.HoldRefreshResponse = true;
        var pendingRefresh = Check();
        await backchannel.RefreshProcessed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.True(await AdminPost("/api/v1/auth/logout") is 0 or 200 or 302);
        backchannel.ReleaseRefresh.TrySetResult();
        Assert.Equal(401, await pendingRefresh);
        Assert.Null(await tickets.RetrieveAsync(sessionId));
        Assert.Equal(401, await Check());
        // Both logout paths retain local business identities and roles.

        Assert.Equal(memberId, (await members.GetByTenantAndUserAsync(tenantId, userId))!.Id);
        Assert.Equal(userId, (await oasis.Services.GetRequiredService<IUserRepository>().GetByExternalIdentityAsync(new oasis.application.Identity.ExternalIdentityKey(issuer, auth.UserId)))!.Id);
    }

    private sealed class PreparedRefresher(OpenIddictOasisTokenRefresher inner, AuthBackchannel faults) : IOasisTokenRefresher
    {
        public Task<bool> PrepareAsync(CancellationToken ct) => faults.PrepareUnavailable ? Task.FromResult(false) : inner.PrepareAsync(ct);
        public Task<OasisRefreshResult> RefreshAsync(string refreshToken, CancellationToken ct) => inner.RefreshAsync(refreshToken, ct);
    }

    private sealed class AuthBackchannel(SecurityProtocolFixture auth) : IHttpClientFactory
    {
        public int RefreshRequests;
        public bool UserinfoUnavailable, LoseRefreshResponse, TemporaryRefreshFailure, SlowUserinfo, HoldRefreshResponse, PrepareUnavailable;
        public readonly TaskCompletionSource RefreshProcessed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource ReleaseRefresh = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public HttpClient CreateClient(string name) => new(new Handler(this, auth.Host.Server.CreateHandler()));
        private sealed class Handler(AuthBackchannel owner, HttpMessageHandler inner) : DelegatingHandler(inner)
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            {
                if (request.RequestUri!.AbsolutePath == "/connect/userinfo" && owner.UserinfoUnavailable)
                    return new(HttpStatusCode.ServiceUnavailable);
                if (request.RequestUri!.AbsolutePath == "/connect/userinfo" && owner.SlowUserinfo)
                    await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                var refresh = request.RequestUri.AbsolutePath == "/connect/token" && request.Content is not null
                    && (await request.Content.ReadAsStringAsync(ct)).Contains("grant_type=refresh_token", StringComparison.Ordinal);
                if (refresh) Interlocked.Increment(ref owner.RefreshRequests);
                if (refresh && owner.TemporaryRefreshFailure) return new(HttpStatusCode.ServiceUnavailable);
                var response = await base.SendAsync(request, ct);
                if (refresh && owner.HoldRefreshResponse)
                {
                    owner.RefreshProcessed.TrySetResult();
                    await owner.ReleaseRefresh.Task.WaitAsync(ct);
                }
                if (refresh && owner.LoseRefreshResponse)
                {
                    response.Dispose();
                    throw new HttpRequestException("synthetic response lost after Auth processed rotation");
                }
                return response;
            }
        }
    }

    private static X509Certificate2 Certificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }

    private sealed class HttpsProxy(WebApplication app, string origin) : IAsyncDisposable
    {
        public string Origin { get; } = origin;
        public HttpClient? Client { get; set; }
        public static async Task<HttpsProxy> StartAsync(X509Certificate2 certificate)
        {
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, endpoint => endpoint.UseHttps(certificate)));
            var app = builder.Build();
            HttpsProxy? proxy = null;
            app.Run(async context =>
            {
                using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), proxy!.Origin + context.Request.Path + context.Request.QueryString);
                if (context.Request.ContentLength > 0) request.Content = new StreamContent(context.Request.Body);
                foreach (var header in context.Request.Headers)
                    if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray())) request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                using var response = await proxy.Client!.SendAsync(request, context.RequestAborted);
                context.Response.StatusCode = (int)response.StatusCode;
                foreach (var header in response.Headers.Concat(response.Content.Headers)) context.Response.Headers[header.Key] = header.Value.ToArray();
                context.Response.Headers.Remove("transfer-encoding");
                await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
            });
            await app.StartAsync();
            proxy = new(app, app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single());
            return proxy;
        }
        public async ValueTask DisposeAsync() { Client?.Dispose(); await app.DisposeAsync(); }
    }
}
