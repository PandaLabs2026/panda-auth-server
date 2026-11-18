using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using PandaAuth.Server.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class PandeskNativeProtocolTests
{
    private const string NativeClient = PandeskNativeIdentity.ClientId;
    private const string Introspector = PandeskNativeIdentity.IntrospectionClientId;
    private const string Audience = PandeskNativeIdentity.Audience;
    private const string ReadScope = PandeskNativeIdentity.ReadScope;
    private const string Callback = "http://127.0.0.1:43824/oauth/callback";

    [Theory]
    [InlineData("http://127.0.0.1:49152/oauth/callback", true)]
    [InlineData("http://127.0.0.1/oauth/callback", false)]
    [InlineData("http://localhost:49152/oauth/callback", false)]
    [InlineData("http://127.0.0.1:49152/other", false)]
    [InlineData("http://127.0.0.1:49152/oauth/callback?other=1", false)]
    [InlineData("http://127.0.0.1:49152/oauth/callback#other", false)]
    public void LoopbackPolicyRequiresTheExactIpv4Callback(string uri, bool expected)
        => Assert.Equal(expected, PandaAuth.Server.Infrastructure.Security.PandeskNativePolicy.IsLoopbackCallback(uri));

    [Theory]
    [InlineData("Production", true, true, true)]
    [InlineData("Staging", true, true, true)]
    [InlineData("Development", false, true, true)]
    [InlineData("Development", true, true, false)]
    [InlineData("Production", false, false, false)]
    public void StartupRejectsEnablingOutsideDevelopmentTenantRouting(string environment, bool routing,
        bool enabled, bool expected)
    {
        var settings = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:Issuer"] = $"https://{Host("t9841")}/",
            ["Auth:TenantRouting:Enabled"] = routing.ToString(),
            ["Auth:PandeskNative:Enabled"] = enabled.ToString(),
            ["ConnectionStrings:Default"] = "Host=127.0.0.1;Database=fixture;Username=fixture",
        }).Build();
        var report = StartupConfiguration.Validate(settings,
            new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = environment }, migrate: false);
        Assert.Equal(expected, report.Errors.Any(error => error.Key == "Auth:PandeskNative:Enabled"));
    }

    [PostgresFact]
    public async Task PublicPkce_ActualIntrospection_ReturnsHumanReadToken_AndRevocationMakesItInactive()
    {
        using var certA = MakeCertificate("t9841");
        using var certB = MakeCertificate("t9842");
        var issuerA = LoopbackIssuer("t9841");
        await using var fixture = await CreateIssuerAsync("t9841", issuerA, certA);
        var issuerB = LoopbackIssuer("t9842");
        await using var other = await CreateIssuerAsync("t9842", issuerB, certB);
        await fixture.EnableTotpAsync(administrator: false);
        await other.EnableTotpAsync(administrator: false);
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var otherSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await RegisterAsync(fixture, secret);
        await RegisterAsync(other, otherSecret);
        using var browser = CreateBrowser(issuerA, certA);
        using var otherBrowser = CreateBrowser(issuerB, certB);
        await AssertDiscoveryAsync(browser, issuerA);
        await AssertDiscoveryAsync(otherBrowser, issuerB);
        using var unknownHost = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        unknownHost.Headers.Host = Host("t9843");
        using (var deniedHost = await browser.SendAsync(unknownHost))
            Assert.Equal((HttpStatusCode)421, deniedHost.StatusCode);
        using var tokens = await IssueAsync(fixture, browser);
        using var otherTokens = await IssueAsync(other, otherBrowser);
        var otherAccess = otherTokens.RootElement.GetProperty("access_token").GetString()!;
        var access = tokens.RootElement.GetProperty("access_token").GetString()!;
        using (var foreignAtA = await IntrospectAsync(browser, secret, otherAccess))
        using (var foreignAtB = await IntrospectAsync(otherBrowser, otherSecret, access))
        using (var localAtB = await IntrospectAsync(otherBrowser, otherSecret, otherAccess))
        {
            Assert.False(foreignAtA.RootElement.GetProperty("active").GetBoolean());
            Assert.False(foreignAtB.RootElement.GetProperty("active").GetBoolean());
            Assert.True(localAtB.RootElement.GetProperty("active").GetBoolean());
            Assert.Equal(issuerB.AbsoluteUri, localAtB.RootElement.GetProperty("iss").GetString());
        }

        var refresh = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        using (var inspected = await IntrospectAsync(browser, secret, access))
        {
            var token = inspected.RootElement;
            Assert.True(token.GetProperty("active").GetBoolean());
            Assert.Equal(issuerA.AbsoluteUri, token.GetProperty("iss").GetString());
            Assert.Equal(fixture.UserId, token.GetProperty("sub").GetString());
            Assert.Equal(PandaAuthClaims.SubjectTypes.Human, token.GetProperty(PandaAuthClaims.SubjectType).GetString());
            Assert.Equal(new[] { Audience, Introspector }.Order(),
                token.GetProperty("aud").EnumerateArray().Select(value => value.GetString()).Order());
            Assert.Contains(ReadScope, token.GetProperty("scope").GetString()!.Split(' '));
            Assert.DoesNotContain("api", token.GetProperty("scope").GetString()!.Split(' '));
        }

        using var refreshed = await PostAsync(browser, PandaAuthEndpoints.Token, new()
        {
            ["client_id"] = NativeClient, ["grant_type"] = GrantTypes.RefreshToken, ["refresh_token"] = refresh,
        });
        Assert.True(!string.Equals(refresh, refreshed.RootElement.GetProperty("refresh_token").GetString(), StringComparison.Ordinal),
            "The refresh token must rotate.");
        access = refreshed.RootElement.GetProperty("access_token").GetString()!;
        using (var inspected = await IntrospectAsync(browser, secret, access))
        {
            Assert.True(inspected.RootElement.GetProperty("active").GetBoolean());
            Assert.Contains(ReadScope, inspected.RootElement.GetProperty("scope").GetString()!.Split(' '));
        }

        using var forbiddenGrant = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = Introspector, ["client_secret"] = secret, ["grant_type"] = GrantTypes.ClientCredentials,
            ["scope"] = ReadScope,
        });
        using var forbidden = await browser.PostAsync(PandaAuthEndpoints.Token, forbiddenGrant);
        Assert.Equal(HttpStatusCode.BadRequest, forbidden.StatusCode);

        using var revokeForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = NativeClient, ["token"] = access, ["token_type_hint"] = "access_token",
        });
        using var revoke = await browser.PostAsync(PandaAuthEndpoints.Revocation, revokeForm);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        using var revoked = await IntrospectAsync(browser, secret, access);
        Assert.False(revoked.RootElement.GetProperty("active").GetBoolean());
    }

    internal static async Task RegisterAsync(SecurityProtocolFixture fixture, string secret)
    {
        using (var scope = fixture.Host.Services.CreateScope())
        {
            var clients = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = ReadScope,
                Resources = { Audience, Introspector },
            });
            await clients.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = NativeClient,
                ClientType = ClientTypes.Public,
                ApplicationType = ApplicationTypes.Native,
                ConsentType = ConsentTypes.Implicit,
                RedirectUris = { new Uri(PandeskNativeIdentity.LoopbackRegistration) },
                Permissions =
                {
                    Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                    Permissions.Endpoints.Revocation, Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken, Permissions.ResponseTypes.Code,
                    Permissions.Prefixes.Scope + ReadScope,
                },
                Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            });
            await clients.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = Introspector,
                ClientSecret = secret,
                ClientType = ClientTypes.Confidential,
                Permissions = { Permissions.Endpoints.Introspection },
            });
        }
    }

    private static async Task<JsonDocument> IssueAsync(SecurityProtocolFixture fixture, HttpClient browser)
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var state = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24));
        var callback = await fixture.CompleteAuthorizationAsync(browser, QueryHelpers.AddQueryString(PandaAuthEndpoints.Authorization,
            new Dictionary<string, string?>
            {
                ["client_id"] = NativeClient, ["redirect_uri"] = Callback, ["response_type"] = "code",
                ["scope"] = $"openid offline_access {ReadScope}", ["state"] = state,
                ["nonce"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24)),
                ["code_challenge_method"] = "S256",
                ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))),
            }));
        Assert.Equal(Callback, callback.GetLeftPart(UriPartial.Path));
        var values = QueryHelpers.ParseQuery(callback.Query);
        Assert.True(values.TryGetValue("code", out var code));
        Assert.Equal(state, values["state"].ToString());

        return await PostAsync(browser, PandaAuthEndpoints.Token, new()
        {
            ["client_id"] = NativeClient, ["redirect_uri"] = Callback, ["grant_type"] = GrantTypes.AuthorizationCode,
            ["code"] = code.ToString(), ["code_verifier"] = verifier,
        });
    }

    private static string Host(string tenant) => $"{tenant}-auth.s001.pandacloud.cc";

    internal static Uri LoopbackIssuer(string tenant)
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        return new Uri($"https://{Host(tenant)}:{((IPEndPoint)reservation.LocalEndpoint).Port}/");
    }

    internal static X509Certificate2 MakeCertificate(string tenant)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={Host(tenant)}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(Host(tenant));
        if (tenant == "t9841") names.AddDnsName(Host("t9843")); // Unknown route probe still uses validated TLS.
        request.CertificateExtensions.Add(names.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
    }

    internal static Task<SecurityProtocolFixture> CreateIssuerAsync(string tenant, Uri issuer, X509Certificate2 certificate)
        => SecurityProtocolFixture.CreateAsync(settings: new Dictionary<string, string>
        {
            ["Auth:Issuer"] = issuer.AbsoluteUri, ["Auth:TenantRouting:Enabled"] = "true",
            ["Auth:TenantRouting:Bindings:0:TenantId"] = tenant,
            ["Auth:TenantRouting:Bindings:0:Product"] = "PandaAuth",
            ["Auth:PandeskNative:Enabled"] = "true",
        }, configureHost: host => host.UseKestrel(options =>
            options.Listen(IPAddress.Loopback, issuer.Port, listen => listen.UseHttps(certificate))));

    internal static HttpClient CreateBrowser(Uri issuer, X509Certificate2 certificate)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = async (context, cancellationToken) =>
            {
                if (context.DnsEndPoint.Host != issuer.Host || context.DnsEndPoint.Port != issuer.Port)
                    throw new InvalidOperationException("Test browser cannot access a foreign endpoint.");
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(IPAddress.Loopback, issuer.Port, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, remote, _, errors) =>
            (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None
            && remote?.GetCertHashString() == certificate.GetCertHashString();
        return new HttpClient(handler) { BaseAddress = issuer };
    }

    internal static async Task AssertDiscoveryAsync(HttpClient browser, Uri issuer)
    {
        using var response = await browser.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var data = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(issuer.AbsoluteUri, data.RootElement.GetProperty("issuer").GetString());
    }

    private static Task<JsonDocument> IntrospectAsync(HttpClient browser, string secret, string access)
        => PostAsync(browser, PandaAuthEndpoints.Introspection, new()
        {
            ["client_id"] = Introspector, ["client_secret"] = secret, ["token"] = access,
        });

    private static async Task<JsonDocument> PostAsync(HttpClient browser, string path, Dictionary<string, string> fields)
    {
        using var form = new FormUrlEncodedContent(fields);
        using var reply = await browser.PostAsync(path, form);
        Assert.Equal(HttpStatusCode.OK, reply.StatusCode);
        return JsonDocument.Parse(await reply.Content.ReadAsStringAsync());
    }
}
