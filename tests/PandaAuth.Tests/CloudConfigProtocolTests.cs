using System.Net;
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
using Microsoft.Extensions.Options;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class CloudConfigProtocolTests
{
    [CloudConfigPostgresFact]
    public async Task EncryptedHumanToken_ActualIntrospectionExposesBothResourcesAndHumanClaims()
    {
        await using var fixture = await Fixture.CreateAsync(true);
        using var browser = fixture.Browser();
        var token = await fixture.TokenAsync(browser);
        Assert.Equal(5, token.Split('.').Length);
        var inspected = await fixture.IntrospectAsync(browser, token);
        Assert.True(inspected.GetProperty("active").GetBoolean());
        Assert.Equal(CloudConfigScopes.Issuer, inspected.GetProperty("iss").GetString());
        Assert.Equal(new[] { CloudConfigScopes.Audience, CloudConfigScopes.IntrospectionClient }.Order(),
            inspected.GetProperty("aud").EnumerateArray().Select(x => x.GetString()).Order());
        Assert.Equal(PandaAuthClaims.SubjectTypes.Human, inspected.GetProperty(PandaAuthClaims.SubjectType).GetString());
        var age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - inspected.GetProperty(Claims.AuthenticationTime).GetInt64();
        Assert.InRange(age, 0, 60);
        foreach (var name in CloudConfigScopes.All)
            Assert.Contains(name, inspected.GetProperty("scope").GetString()!.Split(' '));
    }

    [CloudConfigPostgresFact]
    public async Task MissingIntrospectorResource_ActualProtocolRefusesIntrospection()
    {
        await using var fixture = await Fixture.CreateAsync(false);
        using var browser = fixture.Browser();
        var token = await fixture.TokenAsync(browser);
        var inspected = await fixture.IntrospectAsync(browser, token);
        Assert.False(inspected.GetProperty("active").GetBoolean());
    }

    private sealed class Factory(string connection) : WebApplicationFactory<Program>
    {
        private readonly ConfigContentRoot _root = new(connection, new Dictionary<string, string>
        {
            ["Auth:Issuer"] = CloudConfigScopes.Issuer,
            ["Auth:HttpsRequired"] = "false", ["Auth:Seed:Enabled"] = "false",
            ["Auth:Seed:CloudConfig:Enabled"] = "true",
            ["Auth:Seed:CloudConfig:ClientSecret"] = "protocol-fixture-secret",
        });
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseContentRoot(_root.Path);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureTestServices(services => services.AddDataProtection().UseEphemeralDataProtectionProvider());
        }
        protected override void Dispose(bool disposing) { base.Dispose(disposing); if (disposing) _root?.Dispose(); }
    }

    private sealed class ConfigContentRoot : IDisposable
    {
        internal string Path { get; }
        internal ConfigContentRoot(string connection, IReadOnlyDictionary<string, string> settings,
            [System.Runtime.CompilerServices.CallerFilePath] string sourceFile = "")
        {
            var parsed = new NpgsqlConnectionStringBuilder(connection);
            if (!Regex.IsMatch(parsed.Database ?? "", "^auth_config_test_[0-9a-f]{32}$"))
                throw new InvalidOperationException("AUTH_CONFIG_CONTENT_ROOT_REFUSED");
            Fixture.ValidateBoundary(parsed, parsed.Database!);
            var baseline = System.IO.Path.GetFullPath("../../src/PandaAuth.Server/appsettings.json",
                System.IO.Path.GetDirectoryName(sourceFile)!);
            var json = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(baseline))!.AsObject();
            foreach (var pair in new Dictionary<string, string>(settings) { ["ConnectionStrings:Default"] = connection })
            {
                var keys = pair.Key.Split(':'); var parent = json;
                foreach (var key in keys[..^1])
                {
                    if (parent[key] is not System.Text.Json.Nodes.JsonObject child)
                        parent[key] = child = new System.Text.Json.Nodes.JsonObject();
                    parent = child;
                }
                parent[keys[^1]] = pair.Value;
            }
            Path = Directory.CreateTempSubdirectory("auth-config-host-").FullName;
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateDirectory(System.IO.Path.Combine(Path, "wwwroot", "brand"));
            var file = System.IO.Path.Combine(Path, "appsettings.json");
            File.WriteAllText(file, json.ToJsonString());
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private const string Verifier = "config-fixture-pkce-verifier-012345678901234567890123456789";
        private const string ConsoleSecret = "console-config-protocol-fixture";
        private readonly string _connection;
        private readonly string _password = "Aa!9" + Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
        private readonly string _introspectionSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        private readonly Factory _factory;
        private Fixture(string connection) { _connection = connection; _factory = new Factory(connection); }

        internal static async Task<Fixture> CreateAsync(bool includeIntrospector)
        {
            var builder = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_CONFIG_TEST_POSTGRES"));
            ValidateBoundary(builder, "postgres");
            await using (var connection = new NpgsqlConnection(builder.ConnectionString))
            {
                await connection.OpenAsync();
                await VerifyNonceAsync(connection);
                builder.Database = "auth_config_test_" + Guid.NewGuid().ToString("N");
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{builder.Database}\"", connection);
                await create.ExecuteNonQueryAsync();
            }
            var fixture = new Fixture(builder.ConnectionString);
            try
            {
                await using (var db = fixture.Context()) await db.Database.MigrateAsync();
                await fixture.SeedAsync(includeIntrospector);
                return fixture;
            }
            catch { await fixture.DisposeAsync(); throw; }
        }

        private async Task SeedAsync(bool includeIntrospector)
        {
            var options = new AuthOptions
            {
                Issuer = CloudConfigScopes.Issuer,
                Seed = new SeedOptions
                {
                    Enabled = true, Admin = new() { Password = "" },
                    Me = new() { Enabled = false }, AdminWeb = new() { Enabled = false },
                    CloudConfig = new() { Enabled = true, ClientSecret = _introspectionSecret },
                    CloudConsoleWeb = new()
                    {
                        Enabled = true, ClientSecret = ConsoleSecret,
                        RedirectUris = ["http://localhost/callback"],
                        PostLogoutRedirectUris = ["http://localhost/logout"],
                    },
                },
            };
            var services = new ServiceCollection();
            services.AddLogging(); services.AddSingleton(Options.Create(options));
            services.AddDbContext<PandaAuthDbContext>(builder => builder.UseNpgsql(_connection).UseOpenIddict());
            services.AddUserStore();
            services.AddOpenIddict().AddCore(builder => builder.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
            await using var provider = services.BuildServiceProvider();
            Assert.True((await provider.GetRequiredService<UserService>().CreateAsync(new PandaUser
            {
                UserName = "config-fixture-user", Email = "config-fixture@example.test", EmailConfirmed = true,
            }, _password)).Succeeded);
            await DbSeeder.SeedAsync(provider);
            if (includeIntrospector) return;
            var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
            foreach (var name in CloudConfigScopes.All)
            {
                var entity = await scopes.FindByNameAsync(name); Assert.NotNull(entity);
                await scopes.UpdateAsync(entity, new OpenIddictScopeDescriptor
                {
                    Name = name, Resources = { CloudConfigScopes.Audience },
                });
            }
        }

        internal HttpClient Browser() => _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(CloudConfigScopes.Issuer), AllowAutoRedirect = false, HandleCookies = true,
        });

        internal async Task<string> TokenAsync(HttpClient browser)
        {
            var authorize = "/connect/authorize?client_id=" + FirstPartyClients.CloudConsoleWeb +
                "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid%20profile%20offline_access%20" +
                string.Join("%20", CloudConfigScopes.All) + "&state=config-state&nonce=config-nonce&code_challenge_method=S256&code_challenge=" +
                Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));
            using var redirect = await browser.GetAsync(authorize);
            Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
            using var page = await browser.GetAsync(redirect.Headers.Location!.PathAndQuery);
            var hidden = Regex.Match(await page.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
            Assert.True(hidden.Success);
            using var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = WebUtility.HtmlDecode(hidden.Groups[1].Value),
                ["UserName"] = "config-fixture-user", ["Password"] = _password, ["ReturnUrl"] = authorize,
            });
            using var login = await browser.PostAsync("/account/login", loginForm);
            Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
            using var authorization = await browser.GetAsync(authorize);
            Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorization.Headers.Location!.Query);
            Assert.Equal("config-state", query["state"].ToString());
            Assert.True(query.ContainsKey("code"));
            using var exchange = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = FirstPartyClients.CloudConsoleWeb, ["client_secret"] = ConsoleSecret,
                ["grant_type"] = GrantTypes.AuthorizationCode, ["code"] = query["code"].ToString(),
                ["redirect_uri"] = "http://localhost/callback", ["code_verifier"] = Verifier,
            });
            using var response = await browser.PostAsync("/connect/token", exchange);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.GetProperty("access_token").GetString()!;
        }

        internal async Task<JsonElement> IntrospectAsync(HttpClient browser, string token)
        {
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = CloudConfigScopes.IntrospectionClient,
                ["client_secret"] = _introspectionSecret, ["token"] = token,
            });
            using var response = await browser.PostAsync("/connect/introspect", form);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.Clone();
        }

        private PandaAuthDbContext Context() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(_connection).UseOpenIddict().Options);
        internal static void ValidateBoundary(NpgsqlConnectionStringBuilder connection, string database)
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "dev", "tmp");
            if (!Regex.IsMatch(connection.Host ?? "", "^" + Regex.Escape(root) + "/authpg-[A-Za-z0-9]+/socket$") ||
                connection.Database != database || connection.Username != "auth_config_fixture_owner" ||
                !Regex.IsMatch(Environment.GetEnvironmentVariable("PANDA_AUTH_CONFIG_TEST_RUN") ?? "", "^[a-f0-9]{32}$"))
                throw new InvalidOperationException("AUTH_CONFIG_FIXTURE_REQUIRED");
        }
        private static async Task VerifyNonceAsync(NpgsqlConnection connection)
        {
            await using var query = new NpgsqlCommand("select current_setting('pandalabs.fixture_id', true)", connection);
            if ((string?)await query.ExecuteScalarAsync() != Environment.GetEnvironmentVariable("PANDA_AUTH_CONFIG_TEST_RUN"))
                throw new InvalidOperationException("AUTH_CONFIG_FIXTURE_NONCE_REQUIRED");
        }
        public async ValueTask DisposeAsync()
        {
            await _factory.DisposeAsync();
            var builder = new NpgsqlConnectionStringBuilder(_connection);
            if (!Regex.IsMatch(builder.Database ?? "", "^auth_config_test_[0-9a-f]{32}$"))
                throw new InvalidOperationException("AUTH_CONFIG_CLEANUP_REFUSED");
            ValidateBoundary(builder, builder.Database!);
            await using var connection = new NpgsqlConnection(_connection);
            await connection.OpenAsync(); await VerifyNonceAsync(connection); await connection.CloseAsync();
            await using var db = Context(); await db.Database.EnsureDeletedAsync();
        }
    }
}

internal sealed class CloudConfigPostgresFactAttribute : FactAttribute
{
    public CloudConfigPostgresFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDA_AUTH_CONFIG_TEST_POSTGRES")))
            Skip = "Requires the isolated nonce-verified Cloud configuration PostgreSQL fixture.";
    }
}
