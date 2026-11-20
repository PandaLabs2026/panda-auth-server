using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class PandaMadeProductProtocolTests
{
    private const string Verifier = "pandamade-protocol-fixture-code-verifier-01234567890123456789";
    private const string ProductCallback = "http://127.0.0.1:5091/auth/signin-oidc";
    private const string StaffCallback = "https://admin.pandamade.net/signin-oidc";
    private const string ProductWebSecret = "pandamade-product-protocol-web-fixture";
    private const string ProductApiSecret = "pandamade-product-protocol-api-fixture";
    private const string StaffWebSecret = "pandamade-staff-protocol-web-fixture";
    private const string StaffApiSecret = "pandamade-staff-protocol-api-fixture";

    [PostgresFact]
    public async Task RealProductAndStaffTokensHaveSeparateResourcesAndRefreshKeepsProductIdentity()
    {
        await using var fixture = await CreateAsync();
        using var product = Browser(fixture);
        using var staff = Browser(fixture);
        var productTokens = await IssueAsync(fixture, product, PandaMadeScopes.ProductWebClient, ProductWebSecret,
            ProductCallback, PandaMadeScopes.ProductAccount);
        var staffTokens = await IssueAsync(fixture, staff, PandaMadeScopes.AdminClient, StaffWebSecret,
            StaffCallback, PandaMadeScopes.Manage);
        var productAccessToken = productTokens.GetProperty("access_token").GetString()!;
        var staffAccessToken = staffTokens.GetProperty("access_token").GetString()!;
        Assert.Equal(5, productAccessToken.Split('.').Length);

        var productClaims = await InspectAsync(product, PandaMadeScopes.ProductApi, ProductApiSecret, productAccessToken);
        AssertIdentity(productClaims, fixture.UserId, PandaMadeScopes.ProductApi, PandaMadeScopes.ProductAccount);
        var staffClaims = await InspectAsync(staff, PandaMadeScopes.Api, StaffApiSecret, staffAccessToken);
        AssertIdentity(staffClaims, fixture.UserId, PandaMadeScopes.Api, PandaMadeScopes.Manage);
        Assert.False((await InspectAsync(product, PandaMadeScopes.Api, StaffApiSecret, productAccessToken)).GetProperty("active").GetBoolean());
        Assert.False((await InspectAsync(staff, PandaMadeScopes.ProductApi, ProductApiSecret, staffAccessToken)).GetProperty("active").GetBoolean());

        var refreshed = await PostAsync(product, "/connect/token", new()
        {
            ["client_id"] = PandaMadeScopes.ProductWebClient, ["client_secret"] = ProductWebSecret,
            ["grant_type"] = GrantTypes.RefreshToken, ["refresh_token"] = productTokens.GetProperty("refresh_token").GetString()!,
        });
        var refreshedClaims = await InspectAsync(product, PandaMadeScopes.ProductApi, ProductApiSecret,
            refreshed.GetProperty("access_token").GetString()!);
        AssertIdentity(refreshedClaims, fixture.UserId, PandaMadeScopes.ProductApi, PandaMadeScopes.ProductAccount);
    }

    [PostgresFact]
    public async Task DevClientRejectsProductionCallbackAndNeitherClientCanRequestTheOtherScope()
    {
        await using var fixture = await CreateAsync();
        using var browser = Browser(fixture);
        await AssertAuthorizeRefusedAsync(browser, PandaMadeScopes.ProductWebClient,
            PandaMadeScopes.ProductSignInCallback, PandaMadeScopes.ProductAccount);
        await AssertAuthorizeRefusedAsync(browser, PandaMadeScopes.ProductWebClient, ProductCallback, PandaMadeScopes.Manage);
        await AssertAuthorizeRefusedAsync(browser, PandaMadeScopes.AdminClient, StaffCallback, PandaMadeScopes.ProductAccount);
    }

    private static async Task<SecurityProtocolFixture> CreateAsync()
    {
        var fixture = await SecurityProtocolFixture.CreateAsync(settings: new Dictionary<string, string>
        {
            ["Auth:Issuer"] = PandaMadeScopes.CloudIssuer,
        });
        try
        {
            await using var scope = fixture.Host.Services.CreateAsyncScope();
            var options = scope.ServiceProvider.GetRequiredService<IOptions<AuthOptions>>().Value;
            options.Seed = new SeedOptions
            {
                Admin = new() { Password = "" }, Me = new() { Enabled = false }, AdminWeb = new() { Enabled = false },
                PandamadeProduct = new() { Enabled = true, WebClientSecret = ProductWebSecret, ApiClientSecret = ProductApiSecret },
                PandamadeAdmin = new()
                {
                    Enabled = true, ClientSecret = StaffWebSecret, RedirectUris = [StaffCallback],
                    PostLogoutRedirectUris = ["https://admin.pandamade.net/signout-callback-oidc"],
                },
                PandamadeApi = new() { Enabled = true, ClientSecret = StaffApiSecret },
            };
            await DbSeeder.SeedAsync(scope.ServiceProvider);
            return fixture;
        }
        catch
        {
            await fixture.DisposeAsync();
            throw;
        }
    }

    private static HttpClient Browser(SecurityProtocolFixture fixture) => fixture.Host.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri(PandaMadeScopes.CloudIssuer), AllowAutoRedirect = false, HandleCookies = true,
    });

    private static string Authorize(string client, string callback, string scope) => QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
    {
        ["client_id"] = client, ["redirect_uri"] = callback, ["response_type"] = ResponseTypes.Code,
        ["scope"] = $"openid offline_access {scope}", ["state"] = "pandamade-fixture-state", ["nonce"] = "pandamade-fixture-nonce",
        ["code_challenge_method"] = CodeChallengeMethods.Sha256,
        ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier))),
    });

    private static async Task<JsonElement> IssueAsync(SecurityProtocolFixture fixture, HttpClient browser, string client,
        string secret, string callback, string scope)
    {
        var redirected = await fixture.CompleteAuthorizationAsync(browser, Authorize(client, callback, scope));
        Assert.Equal(callback, redirected.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(redirected.Query);
        Assert.Equal("pandamade-fixture-state", query["state"].ToString());
        Assert.True(query.ContainsKey("code"), "Authorization did not return a code.");
        return await PostAsync(browser, "/connect/token", new()
        {
            ["client_id"] = client, ["client_secret"] = secret, ["grant_type"] = GrantTypes.AuthorizationCode,
            ["redirect_uri"] = callback, ["code_verifier"] = Verifier, ["code"] = query["code"].ToString(),
        });
    }

    private static Task<JsonElement> InspectAsync(HttpClient browser, string client, string secret, string token) =>
        PostAsync(browser, "/connect/introspect", new() { ["client_id"] = client, ["client_secret"] = secret, ["token"] = token });

    private static async Task<JsonElement> PostAsync(HttpClient browser, string path, Dictionary<string, string> fields)
    {
        using var form = new FormUrlEncodedContent(fields);
        using var response = await browser.PostAsync(path, form);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }

    private static void AssertIdentity(JsonElement claims, string subject, string audience, string scope)
    {
        Assert.True(claims.GetProperty("active").GetBoolean());
        Assert.Equal(PandaMadeScopes.CloudIssuer, claims.GetProperty("iss").GetString());
        Assert.Equal(subject, claims.GetProperty("sub").GetString());
        var aud = claims.GetProperty("aud");
        Assert.Equal(audience, aud.ValueKind == JsonValueKind.Array ? Assert.Single(aud.EnumerateArray()).GetString() : aud.GetString());
        var productScopes = claims.GetProperty("scope").GetString()!.Split(' ')
            .Where(value => value is PandaMadeScopes.ProductAccount or PandaMadeScopes.Manage);
        Assert.Equal(scope, Assert.Single(productScopes));
    }

    private static async Task AssertAuthorizeRefusedAsync(HttpClient browser, string client, string callback, string scope)
    {
        using var response = await browser.GetAsync(Authorize(client, callback, scope));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Contains(Errors.InvalidRequest, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }
}
