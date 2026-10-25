using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

// Real Program + OpenIddict + owned PostgreSQL, no fake authentication scheme.
internal sealed class SecurityProtocolFixture : IAsyncDisposable
{
    private const string Verifier = "security-review-code-verifier-012345678901234567890123456789";
    internal const string Secret = "synthetic-security-protocol-client-secret";
    private readonly string password = "Aa!9" + Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
    internal string ConnectionString { get; }
    internal Factory Host { get; }
    internal string UserId { get; private set; } = "";
    private byte[]? mfaSecret;

    private SecurityProtocolFixture(string connection, Action<IServiceCollection>? configure)
    {
        ConnectionString = connection;
        Host = new Factory(connection, configure);
    }

    internal static async Task<SecurityProtocolFixture> CreateAsync(Action<IServiceCollection>? configure = null)
    {
        var builder = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
        PostgresTestBoundary.ValidateEndpoint(builder, PostgresTestBoundary.SharedMode);
        if (builder.Database != "postgres") throw new InvalidOperationException("Disposable test admin database required.");
        var database = "panda_protocol_test_" + Guid.NewGuid().ToString("N");
        await using (var connection = new NpgsqlConnection(builder.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", connection);
            await command.ExecuteNonQueryAsync();
        }
        builder.Database = database;
        var fixture = new SecurityProtocolFixture(builder.ConnectionString, configure);
        try
        {
            await using (var db = fixture.Context()) await db.Database.MigrateAsync();
            using var scope = fixture.Host.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            var roles = scope.ServiceProvider.GetRequiredService<RoleService>();
            Assert.True((await roles.CreateAsync(new PandaRole { Name = PandaAuthRoles.Admin })).Succeeded);
            var user = new PandaUser { UserName = "security-admin", Email = "security-admin@example.test", EmailConfirmed = true };
            Assert.True((await users.CreateAsync(user, fixture.password)).Succeeded);
            Assert.True((await users.AddToRoleAsync(user, PandaAuthRoles.Admin)).Succeeded);
            fixture.UserId = user.Id;
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }

    internal async Task RegisterClientAsync(string clientId, string? scopeName = null, string? audience = null)
    {
        using var scope = Host.Services.CreateScope();
        if (scopeName is not null)
        {
            var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            if (await scopes.FindByNameAsync(scopeName) is null)
            {
                var resource = new OpenIddictScopeDescriptor { Name = scopeName };
                if (audience is not null) resource.Resources.Add(audience);
                await scopes.CreateAsync(resource);
            }
        }
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId, ClientSecret = Secret, ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri("http://localhost/callback") },
            Permissions =
            {
                Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                Permissions.Endpoints.Revocation, Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken, Permissions.ResponseTypes.Code,
                Permissions.Scopes.Profile, Permissions.Scopes.Email, Permissions.Scopes.Roles,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        };
        if (scopeName is not null) descriptor.Permissions.Add(Permissions.Prefixes.Scope + scopeName);
        await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(descriptor);
    }

    internal HttpClient Browser() => Host.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("http://localhost"), AllowAutoRedirect = false, HandleCookies = true,
    });

    internal string AdminPassword => password;

    internal async Task EnableTotpAsync(bool administrator = true)
    {
        using var scope = Host.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        var user = (await users.FindByIdAsync(UserId))!;
        if (!administrator) Assert.True((await users.RemoveFromRoleAsync(user, PandaAuthRoles.Admin)).Succeeded);
        user.TwoFactorEnabled = true;
        Assert.True((await users.UpdateAsync(user)).Succeeded);
        mfaSecret = RandomNumberGenerator.GetBytes(20);
        var id = Guid.NewGuid();
        var secret = scope.ServiceProvider.GetRequiredService<TotpSecretProtector>().Protect(user.Id, id, mfaSecret);
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor
        {
            Id = id, UserId = user.Id, CreatedAt = DateTimeOffset.UtcNow, ConfirmedAt = DateTimeOffset.UtcNow,
            KeyVersion = secret.KeyVersion, Nonce = secret.Nonce, Ciphertext = secret.Ciphertext, Tag = secret.Tag,
        });
        await db.SaveChangesAsync();
    }

    internal async Task<JsonElement> IssueAsync(HttpClient browser, string clientId, string scopes = "openid roles offline_access",
        Func<Task>? beforeExchange = null, HttpStatusCode expected = HttpStatusCode.OK)
    {
        var authorize = "/connect/authorize?client_id=" + Uri.EscapeDataString(clientId) +
            "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=" + Uri.EscapeDataString(scopes) +
            "&state=security-state&nonce=security-nonce&code_challenge_method=S256&code_challenge=" +
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));
        using var challenge = await browser.GetAsync(authorize);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        using var page = await browser.GetAsync(challenge.Headers.Location!.PathAndQuery);
        var hidden = Regex.Match(await page.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(hidden.Success);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(hidden.Groups[1].Value),
            ["UserName"] = "security-admin", ["Password"] = password, ["ReturnUrl"] = authorize,
        });
        using var login = await browser.PostAsync("/account/login", form);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        if (mfaSecret is not null)
        {
            Assert.StartsWith("/account/mfa/challenge", login.Headers.Location!.OriginalString);
            using var challengePage = await browser.GetAsync(login.Headers.Location);
            var csrf = Regex.Match(await challengePage.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
            Assert.True(csrf.Success);
            // 同一 30 秒时间步内的重复登录会被 TOTP 防重放拒绝（LastAcceptedTimeStep）；
            // 协议测试多次签发属测试编排而非重放，提交前重置时间步标记。
            using (var reset = Host.Services.CreateScope())
            {
                var db = reset.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                var factor = await db.TotpFactors.SingleAsync(item => item.UserId == UserId && item.RevokedAt == null && item.ConfirmedAt != null);
                factor.LastAcceptedTimeStep = null;
                await db.SaveChangesAsync();
            }
            var counter = new byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
            var hash = HMACSHA1.HashData(mfaSecret, counter);
            var offset = hash[^1] & 15;
            var code = (System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(hash.AsSpan(offset, 4)) & int.MaxValue) % 1_000_000;
            using var proof = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = WebUtility.HtmlDecode(csrf.Groups[1].Value),
                ["Code"] = code.ToString("D6"), ["ReturnUrl"] = authorize,
            });
            using var assertion = await browser.PostAsync("/account/mfa/challenge/totp", proof);
            Assert.Equal(HttpStatusCode.Redirect, assertion.StatusCode);
        }
        using var authorization = await browser.GetAsync(authorize);
        Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorization.Headers.Location!.Query);
        Assert.True(query.ContainsKey("code"), "Authorization did not return a code.");
        if (beforeExchange is not null) await beforeExchange();
        using var exchange = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = clientId, ["client_secret"] = Secret, ["grant_type"] = GrantTypes.AuthorizationCode,
            ["code"] = query["code"].ToString(), ["redirect_uri"] = "http://localhost/callback", ["code_verifier"] = Verifier,
        });
        using var response = await browser.PostAsync("/connect/token", exchange);
        Assert.Equal(expected, response.StatusCode);
        using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return result.RootElement.Clone();
    }

    internal static async Task<HttpStatusCode> ReadAdminAsync(HttpClient client, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/admin-api/users");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }

    internal PandaAuthDbContext Context() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
        .UseNpgsql(ConnectionString).UseOpenIddict().Options);

    public async ValueTask DisposeAsync()
    {
        await Host.DisposeAsync();
        var connection = new NpgsqlConnectionStringBuilder(ConnectionString);
        PostgresTestBoundary.ValidateEndpoint(connection, PostgresTestBoundary.SharedMode);
        if (!Regex.IsMatch(connection.Database ?? "", "^panda_protocol_test_[0-9a-f]{32}$"))
            throw new InvalidOperationException("Task-owned database required for cleanup.");
        await PostgresTestBoundary.DropOwnedDatabaseAsync(ConnectionString, "panda_protocol_test_");
    }

    internal sealed class Factory(string connection, Action<IServiceCollection>? configure) : WebApplicationFactory<Program>
    {
        private readonly ProtocolHostContentRoot root = new(connection, new Dictionary<string, string>
        {
            ["Auth:Issuer"] = "http://localhost/", ["Auth:HttpsRequired"] = "false", ["Auth:Seed:Enabled"] = "false",
            ["Auth:LoginMfa:Enabled"] = "true",
        });
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development").UseContentRoot(root.Path);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureTestServices(services =>
            {
                services.AddDataProtection().UseEphemeralDataProtectionProvider();
                configure?.Invoke(services);
            });
        }
        protected override void Dispose(bool disposing) { base.Dispose(disposing); if (disposing) root.Dispose(); }
    }
}
