using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class PandeskNativeProtocolTests
{
    // Proposed names are fixture-only until the owning contract is integrated.
    private const string NativeClient = "pandesk-native";
    private const string Introspector = "oasis-pandesk-introspection";
    private const string Audience = "oasis-pandesk";
    private const string ReadScope = "oasis.pandesk.customers.read";
    private const string Callback = "http://127.0.0.1:43824/oauth/callback";

    [PostgresFact]
    public async Task PublicPkce_ActualIntrospection_ReturnsHumanReadToken_AndRevocationMakesItInactive()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.EnableTotpAsync(administrator: false);
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
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
                RedirectUris = { new Uri("http://127.0.0.1/oauth/callback") },
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

        using var browser = fixture.Browser();
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

        using var tokens = await PostAsync(browser, PandaAuthEndpoints.Token, new()
        {
            ["client_id"] = NativeClient, ["redirect_uri"] = Callback, ["grant_type"] = GrantTypes.AuthorizationCode,
            ["code"] = code.ToString(), ["code_verifier"] = verifier,
        });
        var access = tokens.RootElement.GetProperty("access_token").GetString()!;
        var refresh = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        using (var inspected = await IntrospectAsync(browser, secret, access))
        {
            var token = inspected.RootElement;
            Assert.True(token.GetProperty("active").GetBoolean());
            Assert.Equal("http://localhost/", token.GetProperty("iss").GetString());
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
