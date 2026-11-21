using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class NativeLoginBusinessTokenTests
{
    private const string ClientId = NativeLoginRouteTests.ClientId;
    private const string ResourceScope = "fixture.native.api";
    private const string OtherClient = "another-native-test-client";
    private const string ReadScope = PandeskCustomerRead.Scope;
    private const string Audience = PandeskCustomerRead.Audience;
    private const string Introspector = PandeskCustomerRead.IntrospectionClientId;

    [Theory]
    [InlineData(false, false, false, true)]
    [InlineData(true, false, true, true)]
    [InlineData(true, true, false, false)]
    [InlineData(true, true, true, true)]
    public void BusinessScopeRequiresExactlyTheTwoSignedResources(bool audience, bool introspection, bool extra, bool invalid)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetScopes(ReadScope);
        var resources = new List<string>();
        if (audience) resources.Add(Audience);
        if (introspection) resources.Add(PandeskCustomerRead.IntrospectionAudience);
        if (extra) resources.Add("another-api");
        Assert.Equal(invalid, NativeLoginRoute.HasInvalidPandeskResources(principal.SetResources(resources)));
    }

    [PostgresFact]
    public async Task AppChallenge_IssuesHumanReadTokens_AndRevocationIsIssuerLocal()
    {
        const string firstTenant = "t9876";
        const string secondTenant = "t9877";
        using var firstAuthorityKey = RSA.Create(2048);
        using var secondAuthorityKey = RSA.Create(2048);
        using var firstServerKey = RSA.Create(2048);
        using var secondServerKey = RSA.Create(2048);
        using var firstAuthority = NativeLoginDesktopTlsTests.CreateAuthority(firstAuthorityKey);
        using var secondAuthority = NativeLoginDesktopTlsTests.CreateAuthority(secondAuthorityKey);
        using var firstServer = NativeLoginDesktopTlsTests.CreateServerCertificate(firstAuthority, firstServerKey, NativeLoginRouteTests.FixtureHost(firstTenant));
        using var secondServer = NativeLoginDesktopTlsTests.CreateServerCertificate(secondAuthority, secondServerKey, NativeLoginRouteTests.FixtureHost(secondTenant));
        await using var first = await CreateIssuerAsync(firstTenant, firstServer);
        await using var second = await CreateIssuerAsync(secondTenant, secondServer);
        var firstSecret = await RegisterAsync(first, firstTenant, OtherClient);
        var secondSecret = await RegisterAsync(second, secondTenant);
        Assert.NotEqual(first.UserId, second.UserId);

        using var a = CreateClient(firstTenant, firstServer, first);
        using var b = CreateClient(secondTenant, secondServer, second);
        await AssertBusinessScopeUnavailableToOtherGrantsAsync(a, first);
        var accessA = await IssueAsync(a, first);
        var accessB = await IssueAsync(b, second);
        AssertBusinessToken(await IntrospectAsync(a, firstSecret, accessA), a.BaseAddress!, first.UserId);
        AssertBusinessToken(await IntrospectAsync(b, secondSecret, accessB), b.BaseAddress!, second.UserId);
        Assert.False((await IntrospectAsync(a, firstSecret, accessB)).GetProperty("active").GetBoolean());
        Assert.False((await IntrospectAsync(b, secondSecret, accessA)).GetProperty("active").GetBoolean());

        using var foreignClient = await RevokeAsync(a, OtherClient, accessA);
        AssertBusinessToken(await IntrospectAsync(a, firstSecret, accessA), a.BaseAddress!, first.UserId);
        using var accepted = await RevokeAsync(a, ClientId, accessA);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.False(accepted.Headers.Contains("Set-Cookie"));
        Assert.False((await IntrospectAsync(a, firstSecret, accessA)).GetProperty("active").GetBoolean());
        AssertBusinessToken(await IntrospectAsync(b, secondSecret, accessB), b.BaseAddress!, second.UserId);
        await FreezeAsync(second);
        Assert.False((await IntrospectAsync(b, secondSecret, accessB)).GetProperty("active").GetBoolean());
    }

    [PostgresFact]
    public async Task Resource_scope_requires_issuer_configuration_and_client_registration()
    {
        const string tenant = "t9876";
        using var caKey = RSA.Create(2048);
        using var serverKey = RSA.Create(2048);
        using var ca = NativeLoginDesktopTlsTests.CreateAuthority(caKey);
        using var certificate = NativeLoginDesktopTlsTests.CreateServerCertificate(ca, serverKey, NativeLoginRouteTests.FixtureHost(tenant));
        foreach (var (enabled, permitted) in new[] { (false, true), (true, false), (true, true) })
        {
            await using var issuer = await CreateIssuerAsync(tenant, certificate, enabled);
            var secret = await RegisterAsync(issuer, tenant, permitResourceScope: permitted);
            using var client = CreateClient(tenant, certificate, issuer);
            var token = await IssueAsync(client, issuer);
            var scopes = enabled && permitted ? new[] { ReadScope, ResourceScope } : [ReadScope];
            AssertBusinessToken(await IntrospectAsync(client, secret, token), client.BaseAddress!, issuer.UserId, scopes);
            if (enabled && permitted)
            {
                await AssertBusinessScopeUnavailableToOtherGrantsAsync(client, issuer, ResourceScope);
                using var accepted = await RevokeAsync(client, ClientId, token);
                Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
                Assert.False((await IntrospectAsync(client, secret, token)).GetProperty("active").GetBoolean());
            }
        }
    }

    [PostgresTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Resource_code_exchange_fails_after_registration_changes(bool removeClientPermission)
    {
        const string tenant = "t9876";
        using var caKey = RSA.Create(2048);
        using var serverKey = RSA.Create(2048);
        using var ca = NativeLoginDesktopTlsTests.CreateAuthority(caKey);
        using var certificate = NativeLoginDesktopTlsTests.CreateServerCertificate(ca, serverKey, NativeLoginRouteTests.FixtureHost(tenant));
        await using var issuer = await CreateIssuerAsync(tenant, certificate, resourceAccess: true);
        await RegisterAsync(issuer, tenant, permitResourceScope: true);
        using var client = CreateClient(tenant, certificate, issuer);
        var request = await CreateExchangeRequestAsync(client, issuer);

        using var scope = issuer.Host.Services.CreateScope();
        if (removeClientPermission)
        {
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var registration = Assert.IsAssignableFrom<object>(await applications.FindByClientIdAsync(ClientId));
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, registration);
            Assert.True(descriptor.Permissions.Remove(Permissions.Prefixes.Scope + ResourceScope));
            await applications.UpdateAsync(registration, descriptor);
        }
        else
        {
            var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            var registration = Assert.IsAssignableFrom<object>(await scopes.FindByNameAsync(ResourceScope));
            var descriptor = new OpenIddictScopeDescriptor { Name = ResourceScope, Resources = { Audience, "different-api" } };
            await scopes.UpdateAsync(registration, descriptor);
        }

        var response = await PostAsync(client, PandaAuthEndpoints.Token, request, HttpStatusCode.BadRequest);
        Assert.Equal(Errors.InvalidScope, response.GetProperty("error").GetString());
        Assert.False(response.TryGetProperty("access_token", out _));
    }

    internal static Task<SecurityProtocolFixture> CreateIssuerAsync(string tenant, X509Certificate2 server, bool resourceAccess = false)
    {
        var settings = NativeLoginRouteTests.Settings(tenant);
        if (resourceAccess)
        {
            settings["Auth:NativeLogin:ResourceAccess:Scope"] = ResourceScope;
            settings["Auth:NativeLogin:ResourceAccess:Audiences:0"] = Audience;
            settings["Auth:NativeLogin:ResourceAccess:Audiences:1"] = Introspector;
        }
        return SecurityProtocolFixture.CreateAsync(settings: settings,
            configureHost: factory => factory.UseKestrel(options =>
                options.Listen(IPAddress.Loopback, 0, endpoint => endpoint.UseHttps(server))));
    }

    private static HttpClient CreateClient(string tenant, X509Certificate2 server, SecurityProtocolFixture fixture)
        => CreateLoopbackClient(new Uri($"https://{NativeLoginRouteTests.FixtureHost(tenant)}/"),
            NativeLoginDesktopTlsTests.GetPort(fixture), server);

    internal static HttpClient CreateLoopbackClient(Uri issuer, int listenerPort, X509Certificate2 server)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectCallback = async (context, cancellationToken) =>
            {
                if (context.DnsEndPoint.Host != issuer.Host || context.DnsEndPoint.Port != issuer.Port)
                    throw new InvalidOperationException("The client is bound to a single fixture issuer.");
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(IPAddress.Loopback, listenerPort, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None
            && certificate?.GetCertHashString(HashAlgorithmName.SHA256) == server.GetCertHashString(HashAlgorithmName.SHA256);
        return new HttpClient(handler) { BaseAddress = issuer };
    }

    internal static async Task<string> RegisterAsync(SecurityProtocolFixture fixture, string tenant, string? revocationProbeClient = null, bool permitResourceScope = false)
    {
        await fixture.EnableTotpAsync(administrator: false);
        await NativeLoginRouteTests.RegisterAsync(fixture, ClientId, tenant);
        using var scope = fixture.Host.Services.CreateScope();
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        await scopes.CreateAsync(new OpenIddictScopeDescriptor { Name = ReadScope, Resources = { Audience, Introspector } });
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var client = (await apps.FindByClientIdAsync(ClientId))!;
        var descriptor = new OpenIddictApplicationDescriptor();
        await apps.PopulateAsync(descriptor, client);
        descriptor.Permissions.UnionWith([Permissions.Prefixes.Scope + ReadScope, Permissions.Endpoints.Revocation]);
        if (permitResourceScope)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
                { Name = ResourceScope, Resources = { Audience, Introspector } });
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + ResourceScope);
        }
        await apps.UpdateAsync(client, descriptor);
        if (revocationProbeClient is not null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = revocationProbeClient,
                ClientType = ClientTypes.Public,
                Permissions = { Permissions.Endpoints.Revocation },
            });
        }
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await apps.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = Introspector,
            ClientType = ClientTypes.Confidential,
            ClientSecret = secret,
            Permissions = { Permissions.Endpoints.Introspection },
        });
        return secret;
    }

    private static async Task<Dictionary<string, string>> CreateExchangeRequestAsync(HttpClient client, SecurityProtocolFixture fixture)
    {
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var challenge = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var nonce = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var common = new Dictionary<string, string>
        {
            ["client_id"] = ClientId, ["code_challenge"] = challenge,
            ["code_challenge_method"] = CodeChallengeMethods.Sha256, ["nonce"] = nonce,
        };
        var pending = await PostAsync(client, NativeLoginRouteTests.Path, new(common)
        {
            ["step"] = "password", ["username"] = "security-admin", ["password"] = fixture.AdminPassword,
        }, HttpStatusCode.Accepted);
        var issued = await PostAsync(client, NativeLoginRouteTests.Path, new(common)
        {
            ["step"] = "totp", ["challenge"] = pending.GetProperty("challenge").GetString()!, ["otp"] = fixture.CurrentTotpCode(),
        });
        return new()
        {
            ["client_id"] = ClientId, ["grant_type"] = GrantTypes.AuthorizationCode,
            ["code"] = issued.GetProperty("authorization_code").GetString()!, ["code_verifier"] = verifier,
            ["redirect_uri"] = new Uri(client.BaseAddress!, "connect/native/callback").AbsoluteUri,
        };
    }

    private static async Task<string> IssueAsync(HttpClient client, SecurityProtocolFixture fixture)
    {
        var request = await CreateExchangeRequestAsync(client, fixture);
        var tokens = await PostAsync(client, PandaAuthEndpoints.Token, request);
        Assert.True(tokens.TryGetProperty("id_token", out _));
        Assert.False(tokens.TryGetProperty("refresh_token", out _));
        Assert.InRange(tokens.GetProperty("expires_in").GetInt32(), 1, 600);
        return Assert.IsType<string>(tokens.GetProperty("access_token").GetString());
    }

    private static async Task AssertBusinessScopeUnavailableToOtherGrantsAsync(HttpClient client, SecurityProtocolFixture fixture, string scopeName = ReadScope)
    {
        const string genericClient = "configured-web-and-machine-client";
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var callback = new Uri(client.BaseAddress!, "test/web/callback");
        using var scope = fixture.Host.Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await apps.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = genericClient,
            ClientType = ClientTypes.Confidential,
            ClientSecret = secret,
            RedirectUris = { callback },
            Permissions =
            {
                Permissions.Endpoints.Token, Permissions.Endpoints.Authorization, Permissions.GrantTypes.ClientCredentials,
                Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code, Permissions.Prefixes.Scope + scopeName,
            },
        });
        var machine = await PostAsync(client, PandaAuthEndpoints.Token, new()
        {
            ["grant_type"] = GrantTypes.ClientCredentials, ["client_id"] = genericClient, ["client_secret"] = secret, ["scope"] = scopeName,
        }, HttpStatusCode.BadRequest);
        Assert.Equal(Errors.InvalidScope, machine.GetProperty("error").GetString());
        using var web = await client.GetAsync(QueryHelpers.AddQueryString(PandaAuthEndpoints.Authorization, new Dictionary<string, string?>
        {
            ["client_id"] = genericClient, ["redirect_uri"] = callback.AbsoluteUri, ["response_type"] = ResponseTypes.Code,
            ["scope"] = scopeName, ["code_challenge_method"] = CodeChallengeMethods.Sha256,
            ["code_challenge"] = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)),
        }));
        Assert.Equal(HttpStatusCode.Redirect, web.StatusCode);
        Assert.NotNull(web.Headers.Location);
        Assert.Equal(callback.GetLeftPart(UriPartial.Path), web.Headers.Location.GetLeftPart(UriPartial.Path));
        Assert.Equal(Errors.InvalidScope, QueryHelpers.ParseQuery(web.Headers.Location.Query)["error"].ToString());
    }

    private static void AssertBusinessToken(JsonElement token, Uri issuer, string subject, params string[] businessScopes)
    {
        Assert.True(token.GetProperty("active").GetBoolean(), "The business introspector must accept the App access token.");
        Assert.Equal(issuer.AbsoluteUri, token.GetProperty("iss").GetString());
        Assert.Equal(subject, token.GetProperty("sub").GetString());
        Assert.True(token.TryGetProperty(PandaAuthClaims.SubjectType, out var subjectType), "Introspection must expose the human subject type.");
        Assert.Equal(PandaAuthClaims.SubjectTypes.Human, subjectType.GetString());
        Assert.Equal(new[] { Audience, PandeskCustomerRead.IntrospectionAudience }.Order(StringComparer.Ordinal),
            token.GetProperty("aud").EnumerateArray().Select(value => value.GetString()).Order(StringComparer.Ordinal));
        Assert.Equal((businessScopes.Length == 0 ? [ReadScope] : businessScopes).Append(Scopes.OpenId).Order(StringComparer.Ordinal),
            token.GetProperty("scope").GetString()!.Split(' ').Order(StringComparer.Ordinal));
    }

    private static Task<JsonElement> IntrospectAsync(HttpClient client, string secret, string token)
        => PostAsync(client, PandaAuthEndpoints.Introspection, new()
        {
            ["client_id"] = Introspector, ["client_secret"] = secret, ["token"] = token,
        });

    private static async Task FreezeAsync(SecurityProtocolFixture fixture)
    {
        await using var scope = fixture.Host.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var controller = ActivatorUtilities.CreateInstance<AdminUsersController>(services);
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { RequestServices = services },
        };
        await TestGrants.AuthorizeAsync(services, controller, MfaOperations.AdminSetStatus, fixture.UserId,
            TestGrants.Status(UserStatus.Frozen));
        var result = Assert.IsType<OkObjectResult>(
            await controller.SetStatus(fixture.UserId, new AdminUserStatusRequest(UserStatus.Frozen), CancellationToken.None));
        Assert.Equal(UserStatus.Frozen, Assert.IsType<AdminUserSummary>(result.Value).Status);
    }

    private static async Task<HttpResponseMessage> RevokeAsync(HttpClient client, string clientId, string token)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = clientId, ["token"] = token, ["token_type_hint"] = TokenTypeHints.AccessToken,
        });
        return await client.PostAsync(PandaAuthEndpoints.Revocation, form);
    }

    private static async Task<JsonElement> PostAsync(HttpClient client, string path, Dictionary<string, string> fields,
        HttpStatusCode expected = HttpStatusCode.OK)
    {
        using var form = new FormUrlEncodedContent(fields);
        using var response = await client.PostAsync(path, form);
        Assert.Equal(expected, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }
}
