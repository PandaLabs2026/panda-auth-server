using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class RefreshTokenReplayProtocolTests
{
    [PostgresFact]
    public async Task RefreshTokenReplayAfterReuseLeewayIsRejected()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.MigrateAsync();
        await database.SeedAsync();

        await using var factory = new ProtocolFactory(database.ConnectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var verifier = "replay-test-code-verifier-012345678901234567890123456789";
        var authorizationUrl = "/connect/authorize?client_id=replay-client" +
            "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback" +
            "&response_type=code&scope=openid%20offline_access" +
            "&state=replay-state&code_challenge_method=S256&code_challenge=" + CodeChallenge(verifier);

        var loginRedirect = await client.GetAsync(authorizationUrl);
        Assert.Equal(HttpStatusCode.Redirect, loginRedirect.StatusCode);
        var loginPath = RequestPath(loginRedirect.Headers.Location!);

        var loginPage = await client.GetAsync(loginPath);
        var antiForgery = ExtractHiddenValue(await loginPage.Content.ReadAsStringAsync(), "__RequestVerificationToken");
        using var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgery,
            ["UserName"] = "replay-user",
            ["Password"] = "Strong!Pass123",
            ["ReturnUrl"] = authorizationUrl,
        });
        var loggedIn = await client.PostAsync("/account/login", loginForm);
        Assert.Equal(HttpStatusCode.Redirect, loggedIn.StatusCode);

        var authorization = await client.GetAsync(RequestPath(loggedIn.Headers.Location!));
        Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
        var callback = AbsoluteUri(authorization.Headers.Location!);
        Assert.Equal("/callback", callback.AbsolutePath);
        var code = ExtractQueryValue(callback, "code");

        using var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "replay-client",
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = "http://localhost/callback",
            ["code_verifier"] = verifier,
        });
        var exchanged = await client.PostAsync("/connect/token", tokenForm);
        Assert.Equal(HttpStatusCode.OK, exchanged.StatusCode);
        var tokenJson = await exchanged.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(tokenJson?.RefreshToken);
        Assert.NotNull(tokenJson?.AccessToken);

        using var refreshForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "replay-client",
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = tokenJson!.RefreshToken!,
        });
        var refreshed = await client.PostAsync("/connect/token", refreshForm);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var refreshedJson = await refreshed.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(refreshedJson?.RefreshToken);

        using var revokeAccessTokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "replay-client",
            ["token"] = tokenJson.AccessToken!,
            ["token_type_hint"] = "access_token",
        });
        var revoked = await client.PostAsync("/connect/revoke", revokeAccessTokenForm);
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);

        // Token-entry validation makes the database revocation state effective for API calls.
        using var userinfo = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userinfo.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Bearer", tokenJson.AccessToken);
        var userinfoResponse = await client.SendAsync(userinfo);
        Assert.Equal(HttpStatusCode.Unauthorized, userinfoResponse.StatusCode);

        using var revokeRefreshTokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "replay-client",
            ["token"] = refreshedJson!.RefreshToken!,
            ["token_type_hint"] = "refresh_token",
        });
        var revokedRefreshToken = await client.PostAsync("/connect/revoke", revokeRefreshTokenForm);
        Assert.Equal(HttpStatusCode.OK, revokedRefreshToken.StatusCode);

        // The explicit policy permits only a short concurrent retry window.
        await Task.Delay(TimeSpan.FromSeconds(6));
        using var replayForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "replay-client",
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = tokenJson.RefreshToken!,
        });
        var replay = await client.PostAsync("/connect/token", replayForm);
        var replayBody = await replay.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Contains("invalid_grant", replayBody, StringComparison.Ordinal);
    }

    private static string ExtractHiddenValue(string html, string name)
    {
        var match = Regex.Match(html,
            $"name=\\\"{Regex.Escape(name)}\\\"[^>]*value=\\\"([^\\\"]+)\\\"",
            RegexOptions.CultureInvariant);
        return match.Success ? WebUtility.HtmlDecode(match.Groups[1].Value) :
            throw new InvalidOperationException($"Missing hidden form field: {name}");
    }

    private static string ExtractQueryValue(Uri location, string key)
    {
        var value = location.Query.TrimStart('&', '?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(item => item.Split('=', 2))
            .Where(item => item.Length == 2)
            .Select(item => (Key: WebUtility.UrlDecode(item[0]), Value: WebUtility.UrlDecode(item[1])))
            .Single(item => item.Key == key).Value;
        return value;
    }

    private static string RequestPath(Uri location)
        => location.IsAbsoluteUri ? location.PathAndQuery : location.OriginalString;

    private static Uri AbsoluteUri(Uri location)
        => location.IsAbsoluteUri ? location : new Uri(new Uri("http://localhost"), location);

    private static string CodeChallenge(string verifier)
        => Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(verifier)));

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record TokenResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string? AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("refresh_token")] string? RefreshToken);

    private sealed class ProtocolFactory(string connectionString) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:Default", connectionString);
            builder.UseSetting("Auth:Issuer", "http://localhost/");
            builder.UseSetting("Auth:HttpsRequired", "false");
            builder.UseSetting("Auth:Seed:Enabled", "false");
            builder.UseSetting("Logging:LogLevel:Default", "Warning");
            builder.UseSetting("Logging:LogLevel:Microsoft.AspNetCore", "Warning");
        }
    }

    private sealed class TestDatabase(string connectionString) : IAsyncDisposable
    {
        public string ConnectionString => connectionString;

        public static async Task<TestDatabase> CreateAsync()
        {
            var admin = new NpgsqlConnectionStringBuilder(
                Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
            if (admin.Host is not ("127.0.0.1" or "localhost"))
                throw new InvalidOperationException("Protocol tests require a local disposable PostgreSQL.");

            await using var connection = new NpgsqlConnection(admin.ConnectionString);
            await connection.OpenAsync();
            var name = "panda_protocol_test_" + Guid.NewGuid().ToString("N");
            await using var command = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
            await command.ExecuteNonQueryAsync();
            admin.Database = name;
            return new TestDatabase(admin.ConnectionString);
        }

        public async Task MigrateAsync()
        {
            await using var db = Context();
            await db.Database.MigrateAsync();
        }

        public async Task SeedAsync()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(ConnectionString).UseOpenIddict());
            services.AddUserStore();
            services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var user = new PandaUser
            {
                UserName = "replay-user",
                Email = "replay-user@example.com",
                EmailConfirmed = true,
            };
            var userResult = await scope.ServiceProvider.GetRequiredService<UserService>()
                .CreateAsync(user, "Strong!Pass123");
            Assert.True(userResult.Succeeded);

            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "replay-client",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                RedirectUris = { new Uri("http://localhost/callback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.Revocation,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
                },
            });
            await db.SaveChangesAsync();
        }

        private PandaAuthDbContext Context() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(ConnectionString).UseOpenIddict().Options);

        public async ValueTask DisposeAsync()
        {
            await using var db = Context();
            await db.Database.EnsureDeletedAsync();
        }
    }
}
