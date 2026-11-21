using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class NativeAuthorizationCodeCompatibilityTests
{
    private const string FixtureEndpoint = "/test-only/pandesk-authorization";
    private const string UnusedRedirectUri = "http://localhost/pandesk-test-callback";
    private const string ClientId = "pandesk-public-fixture";
    private const string OtherClientId = "other-public-fixture";

    [PostgresFact]
    public async Task PasswordAndTotp_AreVerifiedBeforeCodeExchange()
    {
        var clock = new ChallengeClock();
        await using var fixture = await SecurityProtocolFixture.CreateAsync(services =>
        {
            ConfigureFixtureEndpoint(services);
            services.AddSingleton(clock);
        });
        await RegisterPublicClientAsync(fixture, ClientId);
        await fixture.EnableTotpAsync();
        using var client = CreateHttpClient(fixture);
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var pkce = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        var noPkce = await PostChallengeAsync(client, "", HttpStatusCode.BadRequest, ("step", "password"));
        Assert.Equal(Errors.InvalidRequest, noPkce.GetProperty("error").GetString());
        var plainPkce = await PostChallengeAsync(client, verifier, HttpStatusCode.BadRequest,
            ("step", "password"), ("code_challenge_method", CodeChallengeMethods.Plain));
        Assert.Equal(Errors.InvalidRequest, plainPkce.GetProperty("error").GetString());

        var badPassword = await PostChallengeAsync(client, pkce, HttpStatusCode.Unauthorized,
            ("step", "password"), ("username", "security-admin"), ("password", "wrong-password"));
        Assert.Equal("invalid_credentials", badPassword.GetProperty("error").GetString());
        Assert.False(badPassword.TryGetProperty("challenge", out _));

        var pending = await StartChallengeAsync(client, pkce, fixture.AdminPassword);
        var otherPkce = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        await PostChallengeAsync(client, otherPkce, HttpStatusCode.Conflict,
            ("step", "totp"), ("challenge", pending), ("otp", fixture.CurrentTotpCode()));
        var badTotp = await PostChallengeAsync(client, pkce, HttpStatusCode.Unauthorized,
            ("step", "totp"), ("challenge", pending), ("otp", "invalid"));
        Assert.Equal("invalid_credentials", badTotp.GetProperty("error").GetString());
        var retry = Assert.IsType<string>(badTotp.GetProperty("challenge").GetString());
        Assert.NotEqual(pending, retry);

        await PostChallengeAsync(client, pkce, HttpStatusCode.Conflict,
            ("step", "totp"), ("challenge", pending), ("otp", fixture.CurrentTotpCode()));
        var result = await PostChallengeAsync(client, pkce, HttpStatusCode.OK,
            ("step", "totp"), ("challenge", retry), ("otp", fixture.CurrentTotpCode()));
        var code = Assert.IsType<string>(result.GetProperty("authorization_code").GetString());
        await AssertExchangeAsync(client, code, ClientId, verifier, HttpStatusCode.OK);
        await PostChallengeAsync(client, pkce, HttpStatusCode.Conflict,
            ("step", "totp"), ("challenge", retry), ("otp", fixture.CurrentTotpCode()));
    }

    [PostgresFact]
    public async Task CancelledExpiredOrStaleChallenge_CannotIssueAnAuthorizationCode()
    {
        var clock = new ChallengeClock();
        await using var fixture = await SecurityProtocolFixture.CreateAsync(services =>
        {
            ConfigureFixtureEndpoint(services);
            services.AddSingleton(clock);
        });
        await RegisterPublicClientAsync(fixture, ClientId);
        await fixture.EnableTotpAsync();
        using var client = CreateHttpClient(fixture);
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var pkce = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var cancelled = await StartChallengeAsync(client, pkce, fixture.AdminPassword);
        var result = await PostChallengeAsync(client, pkce, HttpStatusCode.OK, ("step", "cancel"), ("challenge", cancelled));
        Assert.Equal("cancelled", result.GetProperty("status").GetString());
        Assert.False(result.TryGetProperty("authorization_code", out _));
        await PostChallengeAsync(client, pkce, HttpStatusCode.Conflict,
            ("step", "totp"), ("challenge", cancelled), ("otp", fixture.CurrentTotpCode()));

        var original = await StartChallengeAsync(client, pkce, fixture.AdminPassword);
        clock.Advance(TimeSpan.FromMinutes(4));
        var badTotp = await PostChallengeAsync(client, pkce, HttpStatusCode.Unauthorized,
            ("step", "totp"), ("challenge", original), ("otp", "invalid"));
        var expiring = Assert.IsType<string>(badTotp.GetProperty("challenge").GetString());
        clock.Advance(TimeSpan.FromMinutes(1));
        await PostChallengeAsync(client, pkce, HttpStatusCode.Conflict,
            ("step", "totp"), ("challenge", expiring), ("otp", fixture.CurrentTotpCode()));

        var stale = await StartChallengeAsync(client, pkce, fixture.AdminPassword);
        using (var scope = fixture.Host.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            var user = Assert.IsType<PandaUser>(await users.FindByIdAsync(fixture.UserId));
            user.SecurityStamp = Guid.NewGuid().ToString("N");
            Assert.True((await users.UpdateAsync(user)).Succeeded);
        }
        await PostChallengeAsync(client, pkce, HttpStatusCode.Conflict,
            ("step", "totp"), ("challenge", stale), ("otp", fixture.CurrentTotpCode()));
    }

    private static async Task<string> StartChallengeAsync(HttpClient client, string pkce, string password)
    {
        var pending = await PostChallengeAsync(client, pkce, HttpStatusCode.Accepted,
            ("step", "password"), ("username", "security-admin"), ("password", password));
        Assert.Equal("totp", pending.GetProperty("next_step").GetString());
        return Assert.IsType<string>(pending.GetProperty("challenge").GetString());
    }

    private static async Task<JsonElement> PostChallengeAsync(
        HttpClient client, string pkce, HttpStatusCode expected, params (string Key, string Value)[] fields)
    {
        var form = new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = UnusedRedirectUri,
            ["response_type"] = ResponseTypes.Code,
            ["code_challenge"] = pkce,
            ["code_challenge_method"] = CodeChallengeMethods.Sha256,
        };
        foreach (var (key, value) in fields) form[key] = value;
        using var response = await client.PostAsync(FixtureEndpoint, new FormUrlEncodedContent(form));
        Assert.Equal(expected, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.True(response.Headers.CacheControl?.NoStore == true);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (expected != HttpStatusCode.OK) Assert.False(body.TryGetProperty("authorization_code", out _));
        if (expected == HttpStatusCode.Conflict) Assert.Equal("invalid_challenge", body.GetProperty("error").GetString());
        return body;
    }

    private sealed class ChallengeClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan elapsed) => now += elapsed;
    }

    [PostgresFact]
    public async Task JsonAuthorizationCode_UsesTheExistingPkceExchangeAndCanOnlyBeRedeemedOnce()
    {
        // This test-only endpoint starts after successful authentication. It exercises OpenIddict's
        // code creation and exchange with the real Server pipeline, independent of challenge steps.
        await using var fixture = await SecurityProtocolFixture.CreateAsync(ConfigureFixtureEndpoint);
        await RegisterPublicClientAsync(fixture, ClientId);
        await RegisterPublicClientAsync(fixture, OtherClientId);
        using var client = CreateHttpClient(fixture);

        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var challenge = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var firstCode = await IssueAsync(client, challenge);
        await AssertExchangeAsync(client, firstCode, ClientId, verifier, HttpStatusCode.OK);
        await AssertExchangeAsync(client, firstCode, ClientId, verifier, HttpStatusCode.BadRequest);

        var wrongVerifierCode = await IssueAsync(client, challenge);
        await AssertExchangeAsync(client, wrongVerifierCode, ClientId, new string('X', 43), HttpStatusCode.BadRequest);

        var wrongClientCode = await IssueAsync(client, challenge);
        await AssertExchangeAsync(client, wrongClientCode, OtherClientId, verifier, HttpStatusCode.BadRequest);

        await using var otherIssuer = await SecurityProtocolFixture.CreateAsync(
            settings: new Dictionary<string, string> { ["Auth:Issuer"] = "https://other.example.test/" });
        await RegisterPublicClientAsync(otherIssuer, ClientId);
        using var otherIssuerClient = CreateHttpClient(otherIssuer);
        var issuerBoundCode = await IssueAsync(client, challenge);
        await AssertExchangeAsync(otherIssuerClient, issuerBoundCode, ClientId, verifier, HttpStatusCode.BadRequest);
    }

    private static async Task AssertExchangeAsync(
        HttpClient client, string code, string clientId, string codeVerifier, HttpStatusCode expected)
    {
        using var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = GrantTypes.AuthorizationCode,
            ["client_id"] = clientId,
            ["redirect_uri"] = UnusedRedirectUri,
            ["code"] = code,
            ["code_verifier"] = codeVerifier,
        }));
        Assert.Null(response.Headers.Location);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (expected != response.StatusCode)
        {
            var details = body.EnumerateObject()
                .Where(field => field.Name is "error" or "error_description" or "title" or "detail" or "code")
                .Select(field => $"{field.Name}={field.Value}");
            Assert.Fail($"Expected {expected}, got {response.StatusCode}. {string.Join(", ", details)}");
        }
        if (expected == HttpStatusCode.OK)
            Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("access_token").GetString()));
        else
            Assert.Equal(Errors.InvalidGrant, body.GetProperty("error").GetString());
    }

    private static HttpClient CreateHttpClient(SecurityProtocolFixture fixture)
        => fixture.Host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost"), AllowAutoRedirect = false, HandleCookies = false,
        });

    private static async Task<string> IssueAsync(HttpClient client, string challenge)
    {
        using var response = await client.PostAsync(FixtureEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = UnusedRedirectUri,
            ["response_type"] = ResponseTypes.Code,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = CodeChallengeMethods.Sha256,
        }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.True(response.Headers.CacheControl?.NoStore == true);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return Assert.IsType<string>(body.GetProperty("authorization_code").GetString());
    }

    private static async Task RegisterPublicClientAsync(SecurityProtocolFixture fixture, string clientId)
    {
        using var scope = fixture.Host.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId, ClientType = ClientTypes.Public, ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri(UnusedRedirectUri) },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        });
    }

    private static void ConfigureFixtureEndpoint(IServiceCollection services)
    {
        services.AddSingleton(new NativeLoginRoute.Settings(ClientId));
        services.Configure<OpenIddictServerOptions>(options => options.AuthorizationEndpointUris.Add(new Uri(FixtureEndpoint, UriKind.Relative)));
        services.Configure<OpenIddictServerAspNetCoreOptions>(options => options.EnableAuthorizationEndpointPassthrough = false);
        services.AddOpenIddict().AddServer(options =>
        {
            options.AddEventHandler<OpenIddictServerEvents.HandleAuthorizationRequestContext>(handler => handler
                .UseInlineHandler(async context =>
                {
                    var request = context.Transaction.GetHttpRequest();
                    if (request?.Path != FixtureEndpoint) return;

                    var requestServices = request.HttpContext.RequestServices;
                    var clock = requestServices.GetService<ChallengeClock>();
                    var user = clock is null
                        ? await requestServices.GetRequiredService<UserService>().FindByNameAsync("security-admin")
                        : await HandleFixtureChallengeAsync(context, request, clock);
                    if (user is null) return;

                    var authenticatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                    var identity = new ClaimsIdentity([
                        new Claim(PandaAuthClaims.SecurityVersion, AccountSecurityVersion.From(user)),
                        new Claim(LoginSessionService.AuthenticatedAtClaim, authenticatedAt),
                        new Claim(PandaAuthClaims.SsoSessionId, Guid.NewGuid().ToString("N")),
                    ], "fixture");
                    if (clock is not null)
                    {
                        identity.AddClaim(new Claim(MfaClaimTypes.Method, MfaClaimTypes.Totp));
                        identity.AddClaim(new Claim(MfaClaimTypes.VerifiedAt, authenticatedAt));
                    }
                    var authorization = ActivatorUtilities.CreateInstance<AuthorizationController>(requestServices);
                    authorization.ControllerContext = new ControllerContext { HttpContext = request.HttpContext };
                    context.SignIn(await authorization.CreatePrincipalAsync(user, context.Request.GetScopes(), new ClaimsPrincipal(identity)));
                }).SetOrder(int.MinValue + 200_000));
            options.AddEventHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>(handler => handler
                .UseInlineHandler(async context =>
                {
                    var request = context.Transaction.GetHttpRequest();
                    if (request?.Path != FixtureEndpoint) return;

                    var response = request.HttpContext.Response;
                    response.Headers.CacheControl = "no-store";
                    if (context.AuthorizationCode is { } code)
                        await response.WriteAsJsonAsync(new { authorization_code = code });
                    else if (context.Error is { } error)
                    {
                        response.StatusCode = StatusCodes.Status400BadRequest;
                        await response.WriteAsJsonAsync(new { error });
                    }
                    else return;
                    context.HandleRequest();
                }).SetOrder(int.MinValue + 200_000));
        });
    }

    // Test host only. Password and MFA go through the existing server validators, while
    // the fixture owns the experimental HTTP shape and challenge state.
    private static async Task<PandaUser?> HandleFixtureChallengeAsync(
        OpenIddictServerEvents.HandleAuthorizationRequestContext context, HttpRequest request, ChallengeClock clock)
    {
        var ct = request.HttpContext.RequestAborted;
        var services = request.HttpContext.RequestServices;
        var response = request.HttpContext.Response;
        var authorization = context.Request;
        if (authorization.CodeChallengeMethod != CodeChallengeMethods.Sha256 || authorization.CodeChallenge is not { } pkce)
            return await ReplyAsync(400, new { error = "invalid_request" });

        var binding = new NativeLoginBinding(TenantId.Parse("t9876"), context.Options.Issuer!, authorization.ClientId!,
            pkce, authorization.Scope, authorization.GetResources(), authorization.RedirectUri);
        var store = new MfaChallengeStore(services.GetRequiredService<PandaAuthDbContext>(), clock);
        var flow = ActivatorUtilities.CreateInstance<NativeLoginChallengeService>(services, store, clock);
        var form = await request.ReadFormAsync(ct);
        var step = form["step"].ToString();
        var remoteIp = request.HttpContext.Connection.RemoteIpAddress?.ToString();
        NativeLoginResult result;
        if (step == "password")
        {
            result = await flow.StartAsync(binding, form["username"].ToString(), form["password"].ToString(),
                remoteIp, request.Headers.UserAgent.ToString(), ct);
        }
        else if (step is ("totp" or "cancel") && Guid.TryParseExact(form["challenge"].ToString(), "N", out var handle))
        {
            result = step == "cancel"
                ? await flow.CancelAsync(binding, handle, remoteIp, ct)
                : await flow.VerifyTotpAsync(binding, handle, form["otp"].ToString(), remoteIp, ct);
        }
        else
        {
            return await ReplyAsync(400, new { error = "invalid_request" });
        }

        return result switch
        {
            { Status: NativeLoginStatus.TotpRequired, Challenge: { } next } =>
                await ReplyAsync(202, new { next_step = "totp", challenge = next.ToString("N") }),
            { Status: NativeLoginStatus.InvalidCredentials, Challenge: { } retry } =>
                await ReplyAsync(401, new { error = "invalid_credentials", challenge = retry.ToString("N") }),
            { Status: NativeLoginStatus.InvalidCredentials } => await ReplyAsync(401, new { error = "invalid_credentials" }),
            { Status: NativeLoginStatus.InvalidChallenge } => await ReplyAsync(409, new { error = "invalid_challenge" }),
            { Status: NativeLoginStatus.Cancelled } => await ReplyAsync(200, new { status = "cancelled" }),
            { Status: NativeLoginStatus.RateLimited } => await RateLimitedAsync(),
            { Status: NativeLoginStatus.Verified, User: { } user } => user,
            _ => throw new InvalidOperationException("Unexpected native login result."),
        };

        Task<PandaUser?> RateLimitedAsync()
        {
            response.Headers.RetryAfter = "60";
            return ReplyAsync(429, new { error = "rate_limited" });
        }

        async Task<PandaUser?> ReplyAsync(int status, object payload)
        {
            response.StatusCode = status;
            response.Headers.CacheControl = "no-store";
            await response.WriteAsJsonAsync(payload, ct);
            context.HandleRequest();
            return null;
        }
    }
}
