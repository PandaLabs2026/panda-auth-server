using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public class PortalAuthTimeProtocolTests
{
    [PostgresFact]
    public async Task RealLoginCookie_CodePkce_SignedIdTokenPreservesOriginalNumericTimeAndMinimalName()
    {
        await using var fixture = await ProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        var original = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        var authorize = fixture.AuthorizationUrl(profile: true);
        await fixture.LoginAsync(client, authorize);
        fixture.Clock.Advance(TimeSpan.FromMinutes(2));
        var token = await fixture.CodeExchangeAsync(client, authorize);
        var payload = await fixture.ValidateIdTokenAsync(client, token);

        Assert.True(payload.GetProperty(Claims.AuthenticationTime).ValueKind == JsonValueKind.Number);
        Assert.Equal(original, payload.GetProperty(Claims.AuthenticationTime).GetInt64());
        Assert.NotEqual(original, payload.GetProperty(Claims.IssuedAt).GetInt64());
        Assert.Equal("portal-time-user", payload.GetProperty(Claims.Name).GetString());
        foreach (var type in new[] { LoginSessionService.AuthenticatedAtClaim, MfaClaimTypes.Method,
                     MfaClaimTypes.VerifiedAt, Claims.Role, Claims.Email, "nickname" })
            Assert.False(payload.TryGetProperty(type, out _));
        Assert.False(token.TryGetProperty("refresh_token", out _));
    }

    [PostgresFact]
    public async Task SignedIdToken_WithoutProfileOmitsName_AndMetadataIssuerHasExactSlash()
    {
        await using var fixture = await ProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        var authorize = fixture.AuthorizationUrl(profile: false);
        await fixture.LoginAsync(client, authorize);
        var payload = await fixture.ValidateIdTokenAsync(client, await fixture.CodeExchangeAsync(client, authorize));
        Assert.False(payload.TryGetProperty(Claims.Name, out _));
        using var discovery = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        Assert.Equal("http://localhost/", discovery.RootElement.GetProperty("issuer").GetString());
    }

    [PostgresFact]
    public async Task OldProtectedCookie_MissingInvalidOrDuplicateTimeClearsCookieAndRequiresRealLogin()
    {
        await using var fixture = await ProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        var authorize = fixture.AuthorizationUrl(profile: true);
        var cookie = await fixture.LoginAsync(client, authorize);
        foreach (var fault in new[] { "missing", "invalid", "negative", "duplicate" })
        {
            using var oldClient = fixture.Browser(handleCookies: false);
            var oldCookie = fixture.ChangeProtectedCookie(cookie, fault);
            using var request = new HttpRequestMessage(HttpMethod.Get, authorize + "&auth_time=1700000000");
            request.Headers.Add("Cookie", oldCookie);
            var response = await oldClient.SendAsync(request);
            Assert.True(response.StatusCode == HttpStatusCode.Redirect);
            Assert.True(response.Headers.Location?.OriginalString.Contains("/account/login", StringComparison.Ordinal) == true);
            Assert.True(response.Headers.TryGetValues("Set-Cookie", out var deleted) &&
                deleted.Any(value => value.StartsWith(LoginSessionService.Scheme + "=;", StringComparison.Ordinal)));
        }
        using var relogin = fixture.Browser();
        await fixture.LoginAsync(relogin, authorize);
        await fixture.ValidateIdTokenAsync(relogin, await fixture.CodeExchangeAsync(relogin, authorize));
    }

    [PostgresFact]
    public async Task ActualCookieMfaReissue_ProtocolRetainsAuthenticationTimeAndDoesNotDiscloseMfa()
    {
        await using var fixture = await ProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        var authorize = fixture.AuthorizationUrl(profile: true);
        var cookie = await fixture.LoginAsync(client, authorize);
        var original = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        fixture.Clock.Advance(TimeSpan.FromMinutes(2));
        await using var scope = fixture.Factory.Services.CreateAsyncScope();
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "http";
        context.Request.Host = new Microsoft.AspNetCore.Http.HostString("localhost");
        context.Request.Headers.Cookie = cookie;
        await scope.ServiceProvider.GetRequiredService<LoginSessionService>().MarkMfaAsync(context, MfaClaimTypes.WebAuthn);
        var renewed = context.Response.Headers.SetCookie.Single()!.Split(';')[0];
        using var renewedClient = fixture.Browser(handleCookies: false);
        renewedClient.DefaultRequestHeaders.Add("Cookie", renewed);
        var payload = await fixture.ValidateIdTokenAsync(renewedClient,
            await fixture.CodeExchangeAsync(renewedClient, authorize));
        Assert.Equal(original, payload.GetProperty(Claims.AuthenticationTime).GetInt64());
        Assert.False(payload.TryGetProperty(MfaClaimTypes.Method, out _));
        Assert.False(payload.TryGetProperty(MfaClaimTypes.VerifiedAt, out _));
    }

    [PostgresFact]
    public async Task RealSignedCodeTicket_MissingInvalidOrDuplicateTimeReturnsInvalidGrant()
    {
        foreach (var fault in new[] { "missing", "invalid", "duplicate" })
        {
            await using var fixture = await ProtocolFixture.CreateAsync(codeFault: fault);
            using var client = fixture.Browser();
            var authorize = fixture.AuthorizationUrl(profile: true);
            await fixture.LoginAsync(client, authorize);
            var response = await fixture.CodeExchangeResponseAsync(client, authorize);
            Assert.True(response.StatusCode == HttpStatusCode.BadRequest);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(Errors.InvalidGrant, json.RootElement.GetProperty("error").GetString());
        }
    }

    [PostgresFact]
    public async Task ExistingHumanRefreshTicket_PreservesTime_AndMissingTimeReturnsInvalidGrant()
    {
        foreach (var fault in new string?[] { null, "missing" })
        {
            await using var fixture = await ProtocolFixture.CreateAsync(refresh: true, refreshFault: fault);
            using var client = fixture.Browser();
            var authorize = fixture.AuthorizationUrl(profile: true);
            var original = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
            await fixture.LoginAsync(client, authorize);
            var token = await fixture.CodeExchangeAsync(client, authorize);
            fixture.Clock.Advance(TimeSpan.FromMinutes(2));
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = fixture.ClientId, ["grant_type"] = GrantTypes.RefreshToken,
                ["refresh_token"] = token.GetProperty("refresh_token").GetString()!,
            });
            var response = await client.PostAsync("/connect/token", form);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (fault is null)
            {
                Assert.True(response.StatusCode == HttpStatusCode.OK);
                var payload = await fixture.ValidateIdTokenAsync(client, json.RootElement);
                Assert.Equal(original, payload.GetProperty(Claims.AuthenticationTime).GetInt64());
            }
            else
            {
                Assert.True(response.StatusCode == HttpStatusCode.BadRequest);
                Assert.Equal(Errors.InvalidGrant, json.RootElement.GetProperty("error").GetString());
            }
        }
    }

    [PostgresFact]
    public async Task HistoricalUserAndRolePolicyRows_CannotOverrideRealIdTokenTimeOrName()
    {
        await using var fixture = await ProtocolFixture.CreateAsync();
        await using (var scope = fixture.Factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var user = await db.Users.SingleAsync();
            var role = new PandaRole { Name = "historical-role" };
            Assert.True((await scope.ServiceProvider.GetRequiredService<RoleService>().CreateAsync(role)).Succeeded);
            await scope.ServiceProvider.GetRequiredService<UserService>().AddToRolesAsync(user, [role.Name]);
            foreach (var type in new[] { Claims.AuthenticationTime, Claims.Name, LoginSessionService.AuthenticatedAtClaim })
            {
                db.UserClaims.Add(new PandaUserClaim { UserId = user.Id, ClaimType = type, ClaimValue = "999", Scope = Scopes.Profile });
                db.RoleClaims.Add(new PandaRoleClaim { RoleId = role.Id, ClaimType = type, ClaimValue = "999", Scope = Scopes.Profile });
            }
            await db.SaveChangesAsync();
        }
        using var client = fixture.Browser();
        var original = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        var authorize = fixture.AuthorizationUrl(profile: true);
        await fixture.LoginAsync(client, authorize);
        var payload = await fixture.ValidateIdTokenAsync(client, await fixture.CodeExchangeAsync(client, authorize));
        Assert.Equal(original, payload.GetProperty(Claims.AuthenticationTime).GetInt64());
        Assert.Equal("portal-time-user", payload.GetProperty(Claims.Name).GetString());
        Assert.False(payload.TryGetProperty(LoginSessionService.AuthenticatedAtClaim, out _));
    }

    [PostgresFact]
    public async Task MachineClientCredentials_ActualIntrospectionContainsNoHumanAuthenticationTime()
    {
        await using var fixture = await ProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "machine-time-fixture", ["client_secret"] = fixture.MachineSecret,
            ["grant_type"] = GrantTypes.ClientCredentials, ["scope"] = "api",
        });
        var response = await client.PostAsync("/connect/token", form);
        Assert.True(response.StatusCode == HttpStatusCode.OK);
        using var token = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        using var introspection = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "machine-time-fixture", ["client_secret"] = fixture.MachineSecret,
            ["token"] = token.RootElement.GetProperty("access_token").GetString()!,
        });
        var inspected = await client.PostAsync("/connect/introspect", introspection);
        Assert.True(inspected.StatusCode == HttpStatusCode.OK);
        using var claims = JsonDocument.Parse(await inspected.Content.ReadAsStringAsync());
        Assert.True(claims.RootElement.GetProperty("active").GetBoolean());
        Assert.False(claims.RootElement.TryGetProperty(Claims.AuthenticationTime, out _));
    }

    private sealed class MutableClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddMinutes(-3).ToUnixTimeSeconds());
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan span) => _now += span;
    }

    private sealed class ProtocolFactory(string connection, MutableClock clock, string? codeFault, string? refreshFault)
        : WebApplicationFactory<Program>
    {
        private readonly ProtocolHostContentRoot _root = new(connection, new Dictionary<string, string>
        {
            ["Auth:Issuer"] = "http://localhost", ["Auth:HttpsRequired"] = "false", ["Auth:Seed:Enabled"] = "false",
        });
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseContentRoot(_root.Path);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureTestServices(services =>
            {
                services.AddDataProtection().UseEphemeralDataProtectionProvider();
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
                services.AddOpenIddict().AddServer(options =>
                {
                    options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(handler => handler
                        .SetOrder(OpenIddictServerHandlers.GenerateAuthorizationCode.Descriptor.Order - 500)
                        .UseInlineHandler(context =>
                        {
                            if (codeFault is not null && context.AuthorizationCodePrincipal is not null)
                                AlterTime(context.AuthorizationCodePrincipal, codeFault);
                            return default;
                        }));
                    options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(handler => handler
                        .SetOrder(OpenIddictServerHandlers.GenerateRefreshToken.Descriptor.Order - 500)
                        .UseInlineHandler(context =>
                        {
                            if (refreshFault is not null && context.RefreshTokenPrincipal is not null)
                                AlterTime(context.RefreshTokenPrincipal, refreshFault);
                            return default;
                        }));
                });
            });
        }
        protected override void Dispose(bool disposing) { base.Dispose(disposing); _root.Dispose(); }
    }

    private static void AlterTime(ClaimsPrincipal principal, string fault)
    {
        var identity = (ClaimsIdentity)principal.Identity!;
        foreach (var claim in identity.FindAll(Claims.AuthenticationTime).ToArray()) identity.RemoveClaim(claim);
        if (fault == "invalid") identity.AddClaim(new Claim(Claims.AuthenticationTime, "not-a-time"));
        if (fault == "duplicate")
        {
            identity.AddClaim(new Claim(Claims.AuthenticationTime, "1700000000", ClaimValueTypes.Integer64));
            identity.AddClaim(new Claim(Claims.AuthenticationTime, "1700000000", ClaimValueTypes.Integer64));
        }
    }

    private sealed class ProtocolFixture : IAsyncDisposable
    {
        private const string Verifier = "portal-test-code-verifier-012345678901234567890123456789";
        private readonly string _connection;
        private readonly bool _refresh;
        private readonly string _password = "Aa!9" + Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
        public string MachineSecret { get; } = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        public string ClientId => _refresh ? "human-refresh-fixture" : "portal-time-fixture";
        public MutableClock Clock { get; } = new();
        public ProtocolFactory Factory { get; }

        private ProtocolFixture(string connection, bool refresh, string? codeFault, string? refreshFault)
        {
            _connection = connection;
            _refresh = refresh;
            Factory = new ProtocolFactory(connection, Clock, codeFault, refreshFault);
        }

        public static async Task<ProtocolFixture> CreateAsync(bool refresh = false, string? codeFault = null, string? refreshFault = null)
        {
            var admin = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
            if (admin.Host != "127.0.0.1" || admin.Port != 43823 || admin.Database != "postgres")
                throw new InvalidOperationException("Auth protocol fixture requires the approved task loopback cluster/admin database.");
            var name = "panda_auth_portal_test_" + Guid.NewGuid().ToString("N");
            await using (var connection = new NpgsqlConnection(admin.ConnectionString))
            {
                await connection.OpenAsync();
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
                await create.ExecuteNonQueryAsync();
            }
            admin.Database = name;
            var fixture = new ProtocolFixture(admin.ConnectionString, refresh, codeFault, refreshFault);
            try
            {
                await using (var db = fixture.Context()) await db.Database.MigrateAsync();
                await fixture.SeedAsync();
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        private async Task SeedAsync()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(_connection).UseOpenIddict());
            services.AddUserStore();
            services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            Assert.True((await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(
                new PandaUser { UserName = "portal-time-user", Email = "fixture@example.test", EmailConfirmed = true }, _password)).Succeeded);
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId, ClientType = ClientTypes.Public, ConsentType = ConsentTypes.Implicit,
                RedirectUris = { new Uri("http://localhost/callback") },
                PostLogoutRedirectUris = { new Uri("http://localhost/callback/logout") },
                Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.Endpoints.EndSession,
                    Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code, Permissions.Scopes.Profile },
                Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            };
            if (_refresh) descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
            await manager.CreateAsync(descriptor);
            await scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>().CreateAsync(
                new OpenIddictScopeDescriptor { Name = "api", Resources = { "machine-time-fixture" } });
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "machine-time-fixture", ClientType = ClientTypes.Confidential, ClientSecret = MachineSecret,
                Permissions = { Permissions.Endpoints.Token, Permissions.Endpoints.Introspection,
                    Permissions.GrantTypes.ClientCredentials, Permissions.Prefixes.Scope + "api" },
            });
        }

        public HttpClient Browser(bool handleCookies = true)
            => Factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = handleCookies });

        public string AuthorizationUrl(bool profile)
            => "/connect/authorize?client_id=" + ClientId + "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback" +
               "&response_type=code&scope=openid" + (profile ? "%20profile" : "") + (_refresh ? "%20offline_access" : "") +
               "&state=portal-time-state&nonce=portal-time-nonce&code_challenge_method=S256&code_challenge=" +
               Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));

        public async Task<string> LoginAsync(HttpClient client, string authorize)
        {
            var response = await client.GetAsync(authorize);
            Assert.True(response.StatusCode == HttpStatusCode.Redirect);
            var page = await client.GetAsync(response.Headers.Location!.PathAndQuery);
            var hidden = Regex.Match(await page.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
            Assert.True(hidden.Success);
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = WebUtility.HtmlDecode(hidden.Groups[1].Value),
                ["UserName"] = "portal-time-user", ["Password"] = _password, ["ReturnUrl"] = authorize,
            });
            var login = await client.PostAsync("/account/login", form);
            Assert.True(login.StatusCode == HttpStatusCode.Redirect);
            return login.Headers.GetValues("Set-Cookie").Single(value => value.StartsWith(LoginSessionService.Scheme + "=", StringComparison.Ordinal)).Split(';')[0];
        }

        public async Task<HttpResponseMessage> CodeExchangeResponseAsync(HttpClient client, string authorize)
        {
            var authorization = await client.GetAsync(authorize);
            Assert.True(authorization.StatusCode == HttpStatusCode.Redirect);
            var callback = authorization.Headers.Location!;
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(callback.Query);
            Assert.True(query["state"] == "portal-time-state");
            Assert.True(query.ContainsKey("code"));
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = ClientId, ["grant_type"] = GrantTypes.AuthorizationCode, ["code"] = query["code"].ToString(),
                ["redirect_uri"] = "http://localhost/callback", ["code_verifier"] = Verifier,
            });
            return await client.PostAsync("/connect/token", form);
        }

        public async Task<JsonElement> CodeExchangeAsync(HttpClient client, string authorize)
        {
            using var response = await CodeExchangeResponseAsync(client, authorize);
            Assert.True(response.StatusCode == HttpStatusCode.OK);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.Clone();
        }

        public async Task<JsonElement> ValidateIdTokenAsync(HttpClient client, JsonElement token)
        {
            var jwt = token.GetProperty("id_token").GetString()!;
            var keys = new JsonWebKeySet(await client.GetStringAsync("/.well-known/jwks"));
            var handler = new JsonWebTokenHandler { MapInboundClaims = false };
            var validated = await handler.ValidateTokenAsync(jwt, new TokenValidationParameters
            {
                ValidIssuer = "http://localhost/", ValidAudience = ClientId, IssuerSigningKeys = keys.GetSigningKeys(),
                ValidateIssuerSigningKey = true, ValidateIssuer = true, ValidateAudience = true,
                ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true,
            });
            Assert.True(validated.IsValid, "Fixture ID token signature/issuer/audience/lifetime validation failed.");
            using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]));
            Assert.Equal("portal-time-nonce", document.RootElement.GetProperty(Claims.Nonce).GetString());
            return document.RootElement.Clone();
        }

        public string ChangeProtectedCookie(string cookie, string fault)
        {
            var format = Factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(LoginSessionService.Scheme).TicketDataFormat;
            var ticket = format.Unprotect(cookie[(cookie.IndexOf('=') + 1)..])!;
            var identity = (ClaimsIdentity)ticket.Principal.Identity!;
            foreach (var claim in identity.FindAll(LoginSessionService.AuthenticatedAtClaim).ToArray()) identity.RemoveClaim(claim);
            if (fault is "invalid" or "negative") identity.AddClaim(new Claim(LoginSessionService.AuthenticatedAtClaim, fault == "negative" ? "-1" : "not-a-time"));
            if (fault == "duplicate")
            {
                identity.AddClaim(new Claim(LoginSessionService.AuthenticatedAtClaim, "1700000000"));
                identity.AddClaim(new Claim(LoginSessionService.AuthenticatedAtClaim, "1700000000"));
            }
            return LoginSessionService.Scheme + "=" + format.Protect(ticket);
        }

        private PandaAuthDbContext Context() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(_connection).UseOpenIddict().Options);

        public async ValueTask DisposeAsync()
        {
            await Factory.DisposeAsync();
            var builder = new NpgsqlConnectionStringBuilder(_connection);
            if (builder.Host != "127.0.0.1" || builder.Port != 43823 ||
                builder.Database is null || !Regex.IsMatch(builder.Database, "^panda_auth_portal_test_[0-9a-f]{32}$", RegexOptions.CultureInvariant))
                throw new InvalidOperationException("Refusing cleanup outside this task-owned Auth database.");
            await using var db = Context();
            await db.Database.EnsureDeletedAsync();
        }
    }
}
