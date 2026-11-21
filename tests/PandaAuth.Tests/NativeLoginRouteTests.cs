using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
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
    internal const string Path = "/connect/native/authorize-challenge";
    internal const string ClientId = "pandesk-native-isolated";
    private const string OtherClientId = "another-public-client";
    internal static readonly string Host = FixtureHost("t9876");
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

    private const string PilotIssuer = "https://t0000-auth.pandacloud.cc/";
    private const string PilotClient = "pandesk-native-t0000-test";
    private const string PilotSubject = "818cbf0b-3e70-452f-9eae-1fd87aa07fa7";
    private const string PilotRevision = "fcbdd74a-bf92-4fe6-9c3d-fcef0dcd6314";
    private const string PilotConfig = "Auth:NativeLogin:T0000Pilot:";

    [Theory]
    [InlineData("Production")]
    [InlineData("Development")]
    public void T0000PilotRequiresExplicitActivation(string environmentName)
    {
        var settings = PilotSettings();
        var environment = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = environmentName };
        var active = Assert.IsType<NativeLoginRoute.Settings>(ReadPilotSettings(settings, environment));
        Assert.Equal(PilotClient, active.ClientId);
        Assert.Equal(PilotRevision, active.PilotRevision);

        settings[PilotConfig + "Enabled"] = "false";
        Assert.Null(ReadPilotSettings(settings, environment));
        settings[PilotConfig + "Enabled"] = "true";
        settings["Auth:NativeLogin:Enabled"] = "false";
        Assert.Null(ReadPilotSettings(settings, environment));
    }

    [Theory]
    [InlineData("Auth:Issuer", "https://t0000-auth.s001.pandacloud.cc/")]
    [InlineData("Auth:TenantRouting:Enabled", "false")]
    [InlineData("Auth:TenantRouting:Bindings:0:State", "Pending")]
    [InlineData("Auth:TenantRouting:Bindings:0:RouteRevision", "0")]
    [InlineData(PilotConfig + "AllowedSubjects:0", "")]
    [InlineData(PilotConfig + "Revision", "")]
    [InlineData("Auth:NativeLogin:ClientId", " ")]
    public void ProductionPilotRefusesInvalidActivationSettings(string key, string value)
    {
        var settings = PilotSettings();
        settings[key] = value;
        var environment = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = Environments.Production };
        Assert.Throws<InvalidOperationException>(() => ReadPilotSettings(settings, environment));

        var report = StartupConfiguration.Validate(PilotConfiguration(settings), environment, migrate: false);
        Assert.Contains(new ConfigurationError("Auth:NativeLogin", "native_login_invalid"), report.Errors);
    }

    [Fact]
    public void ProductionPilotRefusesPendingRouteShadowingReadyRoute()
    {
        var settings = PilotSettings();
        foreach (var suffix in new[] { "TenantId", "Product", "Zone" })
            settings["Auth:TenantRouting:Bindings:1:" + suffix] = settings["Auth:TenantRouting:Bindings:0:" + suffix];
        settings["Auth:TenantRouting:Bindings:0:State"] = "Pending";
        var environment = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = Environments.Production };
        Assert.Throws<InvalidOperationException>(() => ReadPilotSettings(settings, environment));
    }

    private static NativeLoginRoute.Settings? ReadPilotSettings(Dictionary<string, string> settings, IHostEnvironment environment)
    {
        var configuration = PilotConfiguration(settings);
        var routing = configuration.GetSection("Auth:TenantRouting").Get<TenantRoutingOptions>()!;
        return NativeLoginRoute.ReadSettings(configuration, environment, routing);
    }

    private static IConfiguration PilotConfiguration(Dictionary<string, string> settings)
        => new ConfigurationBuilder().AddInMemoryCollection(settings.Select(pair =>
            new KeyValuePair<string, string?>(pair.Key, pair.Value))).Build();

    [Theory]
    [InlineData("Auth:Issuer", "https://t0000-auth.s001.pandacloud.cc/")]
    [InlineData("Auth:TenantRouting:Bindings:0:TenantId", "t9876")]
    [InlineData("Auth:NativeLogin:T0000Pilot:AllowedSubjects:0", "")]
    [InlineData(PilotConfig + "Revision", "")]
    public void T0000PilotRefusesIncompleteOrWrongBindings(string key, string value)
    {
        var settings = PilotSettings();
        settings[key] = value;
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings.Select(pair => new KeyValuePair<string, string?>(pair.Key, pair.Value))).Build();
        var environment = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = Environments.Development };
        var routing = configuration.GetSection("Auth:TenantRouting").Get<TenantRoutingOptions>()!;
        Assert.Throws<InvalidOperationException>(() => NativeLoginRoute.ReadSettings(configuration, environment, routing));
    }

    [Fact]
    public void DisabledT0000PilotDoesNotFallBackToGenericNativeLogin()
    {
        var settings = PilotSettings();
        settings[PilotConfig + "Enabled"] = "false";
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            settings.Select(pair => new KeyValuePair<string, string?>(pair.Key, pair.Value))).Build();
        var environment = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = Environments.Development };
        var routing = configuration.GetSection("Auth:TenantRouting").Get<TenantRoutingOptions>()!;
        Assert.Null(NativeLoginRoute.ReadSettings(configuration, environment, routing));
    }

    [PostgresTheory]
    [InlineData(true, true, HttpStatusCode.Accepted, PilotConfig + "Enabled", "false", false)]
    [InlineData(true, true, HttpStatusCode.Accepted, PilotConfig + "AllowedSubjects:0", "53a0cb4c-0438-4026-8c0f-57c7e7a84309", false)]
    [InlineData(true, true, HttpStatusCode.Accepted, PilotConfig + "Revision", "83568975-a8ec-481a-bc91-a9f3ef75f250", false)]
    [InlineData(false, true, HttpStatusCode.Unauthorized, null, null, false)]
    [InlineData(true, false, HttpStatusCode.BadRequest, null, null, false)]
    [InlineData(true, true, HttpStatusCode.Accepted, PilotConfig + "AllowedSubjects:0", "53a0cb4c-0438-4026-8c0f-57c7e7a84309", true)]
    public async Task T0000PilotRequiresBothSubjectAdmissionAndReadOnlyScope(
        bool approved, bool readScope, HttpStatusCode expected, string? closedKey, string? closedValue, bool production)
    {
        const string unapprovedSubject = "53a0cb4c-0438-4026-8c0f-57c7e7a84309";
        var settings = PilotSettings();
        if (production) settings["Auth:HttpsRequired"] = "false"; // The existing t0000 host allows HTTP backhaul.
        var pilotUri = new Uri(PilotIssuer);
        using var authorityKey = production ? RSA.Create(2048) : null;
        using var serverKey = production ? RSA.Create(2048) : null;
        using var authority = production ? NativeLoginDesktopTlsTests.CreateAuthority(authorityKey!) : null;
        using var certificate = production
            ? NativeLoginDesktopTlsTests.CreateServerCertificate(authority!, serverKey!, pilotUri.Host) : null;
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: settings,
            userId: approved ? PilotSubject : unapprovedSubject,
            configureHost: certificate is null ? null : factory => factory.UseKestrel(server =>
            {
                server.Listen(IPAddress.Loopback, 0);
                server.Listen(IPAddress.Loopback, 0, listener => listener.UseHttps(certificate));
            }),
            environmentName: production ? Environments.Production : Environments.Development);
        await fixture.EnableTotpAsync();
        using var scope = fixture.Host.Services.CreateScope();
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        await scopes.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = PandeskCustomerRead.Scope,
            Resources = { PandeskCustomerRead.Audience, PandeskCustomerRead.IntrospectionAudience },
        });
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var registration = new OpenIddictApplicationDescriptor
        {
            ClientId = PilotClient,
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri(PilotIssuer + "connect/native/callback") },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        };
        if (readScope) registration.Permissions.Add(Permissions.Prefixes.Scope + PandeskCustomerRead.Scope);
        await applications.CreateAsync(registration);
        using var client = certificate is null ? CreateClient(fixture, PilotIssuer) : LocalClient(pilotUri);

        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var fields = new Dictionary<string, string>
        {
            ["client_id"] = PilotClient,
            ["code_challenge"] = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))),
            ["code_challenge_method"] = CodeChallengeMethods.Sha256,
            ["nonce"] = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)),
            ["step"] = "password",
            ["username"] = "security-admin",
            ["password"] = fixture.AdminPassword,
        };
        if (production)
        {
            var webCallback = new Uri("https://t0000.pandacloud.cc/oidc-test-callback");
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "synthetic-t0000-web",
                ClientType = ClientTypes.Confidential,
                ClientSecret = SecurityProtocolFixture.Secret,
                ConsentType = ConsentTypes.Implicit,
                RedirectUris = { webCallback },
                Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code },
            });
            using var browser = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
            {
                ["client_id"] = "synthetic-t0000-web", ["response_type"] = ResponseTypes.Code,
                ["redirect_uri"] = webCallback.AbsoluteUri, ["scope"] = Scopes.OpenId, ["prompt"] = PromptValues.None,
                ["code_challenge"] = fields["code_challenge"], ["code_challenge_method"] = CodeChallengeMethods.Sha256,
            }));
            Assert.Equal(HttpStatusCode.Redirect, browser.StatusCode);
            var destination = Assert.IsType<Uri>(browser.Headers.Location);
            Assert.Equal(webCallback.AbsoluteUri, destination.GetLeftPart(UriPartial.Path));
            Assert.Equal(Errors.LoginRequired, QueryHelpers.ParseQuery(destination.Query)["error"].ToString());
        }

        using var result = await client.PostAsync(Path, new FormUrlEncodedContent(fields));
        Assert.Equal(expected, result.StatusCode);
        var response = await result.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(response.TryGetProperty("authorization_code", out _));
        if (expected != HttpStatusCode.Accepted)
        {
            Assert.False(response.TryGetProperty("challenge", out _));
            return;
        }

        fields.Remove("username");
        fields.Remove("password");
        fields["step"] = "totp";
        fields["challenge"] = response.GetProperty("challenge").GetString()!;
        fields["otp"] = fixture.CurrentTotpCode();
        using var verified = await client.PostAsync(Path, new FormUrlEncodedContent(fields));
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        var approval = await verified.Content.ReadFromJsonAsync<JsonElement>();
        var exchange = new Dictionary<string, string>
        {
            ["grant_type"] = GrantTypes.AuthorizationCode,
            ["client_id"] = PilotClient,
            ["code"] = approval.GetProperty("authorization_code").GetString()!,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = PilotIssuer + "connect/native/callback",
        };
        if (production)
        {
            using var insecureClient = LocalClient(new UriBuilder(pilotUri) { Scheme = "http", Port = -1 }.Uri);
            using var insecureExchange = await insecureClient.PostAsync("/connect/token", new FormUrlEncodedContent(exchange));
            Assert.Equal(HttpStatusCode.BadRequest, insecureExchange.StatusCode);
            Assert.Equal(Errors.InvalidGrant, (await insecureExchange.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        }
        using var exchanged = await client.PostAsync("/connect/token", new FormUrlEncodedContent(exchange));
        Assert.Equal(HttpStatusCode.OK, exchanged.StatusCode);
        var tokens = await exchanged.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(tokens.TryGetProperty("access_token", out _));
        Assert.True(tokens.TryGetProperty("id_token", out _));
        Assert.False(tokens.TryGetProperty("refresh_token", out _));

        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = PandeskCustomerRead.IntrospectionClientId,
            ClientType = ClientTypes.Confidential,
            ClientSecret = secret,
            Permissions = { Permissions.Endpoints.Introspection },
        });
        var accessToken = tokens.GetProperty("access_token").GetString()!;
        Assert.True(await IsActiveAsync());
        var configuration = fixture.Host.Services.GetRequiredService<IConfiguration>();
        configuration[closedKey!] = closedValue;
        Assert.False(await IsActiveAsync());

        HttpClient LocalClient(Uri origin)
        {
            var listeners = fixture.Host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
            var listener = Assert.Single(listeners.Addresses.Select(value => new Uri(value)), address => address.Scheme == origin.Scheme);
            Assert.True(listener.IsLoopback);
            return NativeLoginBusinessTokenTests.CreateLoopbackClient(origin, listener.Port, certificate!);
        }

        async Task<bool> IsActiveAsync()
        {
            using var reply = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = PandeskCustomerRead.IntrospectionClientId,
                ["client_secret"] = secret,
                ["token"] = accessToken,
            }));
            Assert.Equal(HttpStatusCode.OK, reply.StatusCode);
            var body = await reply.Content.ReadFromJsonAsync<JsonElement>();
            Assert.False(body.TryGetProperty(NativeLoginRoute.PilotRevisionClaim, out _));
            return body.GetProperty("active").GetBoolean();
        }
    }

    private static Dictionary<string, string> PilotSettings() => new()
    {
        ["Auth:Issuer"] = PilotIssuer,
        ["Auth:HttpsRequired"] = "true",
        ["Auth:TenantRouting:Enabled"] = "true",
        ["Auth:TenantRouting:Bindings:0:TenantId"] = "t0000",
        ["Auth:TenantRouting:Bindings:0:Product"] = "PandaAuth",
        ["Auth:TenantRouting:Bindings:0:Zone"] = "",
        ["Auth:NativeLogin:Enabled"] = "true",
        ["Auth:NativeLogin:ClientId"] = PilotClient,
        [PilotConfig + "Enabled"] = "true",
        [PilotConfig + "Revision"] = PilotRevision,
        [PilotConfig + "AllowedSubjects:0"] = PilotSubject,
    };

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

    internal static string FixtureHost(string tenant) =>
        TenantCanonicalHost.For(TenantId.Parse(tenant), TenantProduct.PandaAuth, "s901");

    internal static Dictionary<string, string> Settings(string tenant = "t9876") => new()
    {
        ["Auth:Issuer"] = $"https://{FixtureHost(tenant)}/",
        ["Auth:HttpsRequired"] = "true",
        ["Auth:TenantRouting:Enabled"] = "true",
        ["Auth:TenantRouting:Bindings:0:TenantId"] = tenant,
        ["Auth:TenantRouting:Bindings:0:Product"] = "PandaAuth",
        ["Auth:TenantRouting:Bindings:0:Zone"] = "s901",
        ["Auth:TenantRouting:Bindings:0:State"] = "Ready",
        ["Auth:NativeLogin:Enabled"] = "true",
        ["Auth:NativeLogin:ClientId"] = ClientId,
    };

    internal static async Task RegisterAsync(SecurityProtocolFixture fixture, string clientId, string tenant = "t9876")
    {
        using var scope = fixture.Host.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri($"https://{FixtureHost(tenant)}/connect/native/callback") },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        });
    }
}
