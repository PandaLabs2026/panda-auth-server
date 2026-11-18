using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class NativeLoginRouteTests
{
    private const string Path = "/connect/native/authorize-challenge";
    internal const string ClientId = "pandesk-native-isolated";
    private const string OtherClientId = "another-public-client";
    internal static readonly string Host = TenantCanonicalHost.For(TenantId.Parse("t9876"), TenantProduct.PandaAuth, "s901");
    private static readonly string Issuer = $"https://{Host}/";
    private static readonly string Callback = Issuer + "connect/native/callback";

    [Fact]
    public void NativeRouteCannotBeEnabledInProduction()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:NativeLogin:Enabled"] = "true",
            ["Auth:NativeLogin:ClientId"] = ClientId,
        }).Build();
        var environment = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = Environments.Production };
        Assert.Throws<InvalidOperationException>(() => NativeLoginRoute.ReadSettings(configuration, environment, new TenantRoutingOptions { Enabled = true }));
    }

    [PostgresFact]
    public async Task RouteIsClosedByDefault()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        using var client = CreateClient(fixture, "https://localhost");
        using var response = await client.PostAsync(Path, new FormUrlEncodedContent([]));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [PostgresFact]
    public async Task EnabledRoute_UsesNativeChallengeAndRealTokenEndpoint()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: Settings());
        await RegisterAsync(fixture, ClientId);
        await RegisterAsync(fixture, OtherClientId);
        await fixture.EnableTotpAsync();
        using var client = CreateClient(fixture, Issuer);
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var challenge = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var nonce = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

        using var web = await client.GetAsync(WebAuthorization(OtherClientId));
        Assert.Equal(HttpStatusCode.Redirect, web.StatusCode);
        Assert.Contains("/account/login", web.Headers.Location?.OriginalString);
        using var blockedWeb = await client.GetAsync(WebAuthorization(ClientId));
        Assert.True((int)blockedWeb.StatusCode >= 400);

        using var wrongHost = CreateClient(fixture, "https://localhost");
        await PostAsync(wrongHost, HttpStatusCode.MisdirectedRequest, ("step", "password"));
        using var insecure = CreateClient(fixture, $"http://{Host}");
        await PostAsync(insecure, HttpStatusCode.BadRequest, ("step", "password"));
        await PostAsync(client, HttpStatusCode.BadRequest, ("step", "password"), ("client_id", OtherClientId));
        await PostAsync(client, HttpStatusCode.BadRequest, ("step", "password"), ("redirect_uri", Callback));
        await PostAsync(client, HttpStatusCode.Unauthorized, ("step", "password"),
            ("username", "security-admin"), ("password", "invalid"));

        var initial = await PostAsync(client, HttpStatusCode.Accepted, ("step", "password"),
            ("username", "security-admin"), ("password", fixture.AdminPassword));
        var cancelledHandle = Assert.IsType<string>(initial.GetProperty("challenge").GetString());
        var cancelled = await PostAsync(client, HttpStatusCode.OK, ("step", "cancel"), ("challenge", cancelledHandle));
        Assert.Equal("cancelled", cancelled.GetProperty("status").GetString());
        Assert.False(cancelled.TryGetProperty("authorization_code", out _));
        await PostAsync(client, HttpStatusCode.Conflict, ("step", "totp"), ("challenge", cancelledHandle), ("otp", fixture.CurrentTotpCode()));

        var pending = await PostAsync(client, HttpStatusCode.Accepted, ("step", "password"),
            ("username", "security-admin"), ("password", fixture.AdminPassword));
        Assert.Equal("totp", pending.GetProperty("next_step").GetString());
        var handle = Assert.IsType<string>(pending.GetProperty("challenge").GetString());
        await PostAsync(client, HttpStatusCode.Conflict, ("step", "totp"), ("challenge", handle),
            ("otp", fixture.CurrentTotpCode()), ("nonce", WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32))));
        var authorized = await PostAsync(client, HttpStatusCode.OK, ("step", "totp"),
            ("challenge", handle), ("otp", fixture.CurrentTotpCode()));
        var code = Assert.IsType<string>(authorized.GetProperty("authorization_code").GetString());
        using var exchanged = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = GrantTypes.AuthorizationCode,
            ["client_id"] = ClientId,
            ["code"] = code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = Callback,
        }));
        Assert.Equal(HttpStatusCode.OK, exchanged.StatusCode);
        Assert.Null(exchanged.Headers.Location);
        Assert.False(exchanged.Headers.Contains("Set-Cookie"));
        var tokens = await exchanged.Content.ReadFromJsonAsync<JsonElement>();
        var identityToken = Assert.IsType<string>(tokens.GetProperty("id_token").GetString());
        using var claims = JsonDocument.Parse(WebEncoders.Base64UrlDecode(identityToken.Split('.')[1]));
        Assert.Equal(nonce, claims.RootElement.GetProperty("nonce").GetString());
        Assert.Equal(Issuer, claims.RootElement.GetProperty("iss").GetString());

        string WebAuthorization(string clientId) => QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = clientId, ["redirect_uri"] = Callback, ["response_type"] = ResponseTypes.Code,
            ["code_challenge"] = challenge, ["code_challenge_method"] = CodeChallengeMethods.Sha256,
        });

        async Task<JsonElement> PostAsync(HttpClient browserless, HttpStatusCode status, params (string Name, string Value)[] fields)
        {
            var form = new Dictionary<string, string>
            {
                ["client_id"] = ClientId,
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = CodeChallengeMethods.Sha256,
                ["nonce"] = nonce,
            };
            foreach (var field in fields) form[field.Name] = field.Value;
            using var response = await browserless.PostAsync(Path, new FormUrlEncodedContent(form));
            Assert.Equal(status, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.False(response.Headers.Contains("Set-Cookie"));
            Assert.True(response.Headers.CacheControl?.NoStore == true);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            if (status != HttpStatusCode.OK) Assert.False(body.TryGetProperty("authorization_code", out _));
            return body;
        }
    }

    private static HttpClient CreateClient(SecurityProtocolFixture fixture, string origin)
        => fixture.Host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(origin), AllowAutoRedirect = false, HandleCookies = false,
        });

    internal static Dictionary<string, string> Settings() => new()
    {
        ["Auth:Issuer"] = Issuer,
        ["Auth:HttpsRequired"] = "true",
        ["Auth:TenantRouting:Enabled"] = "true",
        ["Auth:TenantRouting:Bindings:0:TenantId"] = "t9876",
        ["Auth:TenantRouting:Bindings:0:Product"] = "PandaAuth",
        ["Auth:TenantRouting:Bindings:0:Zone"] = "s901",
        ["Auth:TenantRouting:Bindings:0:State"] = "Ready",
        ["Auth:NativeLogin:Enabled"] = "true",
        ["Auth:NativeLogin:ClientId"] = ClientId,
    };

    internal static async Task RegisterAsync(SecurityProtocolFixture fixture, string clientId)
    {
        using var scope = fixture.Host.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri(Callback) },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        });
    }
}
