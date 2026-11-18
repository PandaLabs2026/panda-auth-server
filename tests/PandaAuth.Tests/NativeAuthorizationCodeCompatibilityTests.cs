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
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Security;
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
        services.Configure<OpenIddictServerOptions>(options => options.AuthorizationEndpointUris.Add(new Uri(FixtureEndpoint, UriKind.Relative)));
        services.Configure<OpenIddictServerAspNetCoreOptions>(options => options.EnableAuthorizationEndpointPassthrough = false);
        services.AddOpenIddict().AddServer(options =>
        {
            options.AddEventHandler<OpenIddictServerEvents.HandleAuthorizationRequestContext>(handler => handler
                .UseInlineHandler(async context =>
                {
                    var request = context.Transaction.GetHttpRequest();
                    if (request?.Path != FixtureEndpoint) return;

                    var users = request.HttpContext.RequestServices.GetRequiredService<UserService>();
                    var user = await users.FindByNameAsync("security-admin") ?? throw new InvalidOperationException("Test user missing.");
                    var evidence = new ClaimsPrincipal(new ClaimsIdentity([
                        new Claim(PandaAuthClaims.SecurityVersion, AccountSecurityVersion.From(user)),
                        new Claim(LoginSessionService.AuthenticatedAtClaim, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
                        new Claim(PandaAuthClaims.SsoSessionId, Guid.NewGuid().ToString("N")),
                    ], "fixture"));
                    var authorization = ActivatorUtilities.CreateInstance<AuthorizationController>(request.HttpContext.RequestServices);
                    authorization.ControllerContext = new ControllerContext { HttpContext = request.HttpContext };
                    context.SignIn(await authorization.CreatePrincipalAsync(user, context.Request.GetScopes(), evidence));
                }).SetOrder(int.MinValue + 200_000));
            options.AddEventHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>(handler => handler
                .UseInlineHandler(async context =>
                {
                    var request = context.Transaction.GetHttpRequest();
                    if (request?.Path != FixtureEndpoint || context.AuthorizationCode is not { } code) return;

                    var response = request.HttpContext.Response;
                    response.Headers.CacheControl = "no-store";
                    await response.WriteAsJsonAsync(new { authorization_code = code });
                    context.HandleRequest();
                }).SetOrder(int.MinValue + 200_000));
        });
    }
}
