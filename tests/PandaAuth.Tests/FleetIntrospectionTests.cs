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
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// Fleet 控制面 introspection 契约（真实 OIDC 管线，隔离 PostgreSQL）：introspection 结果
/// 必须暴露受信 subject_type 与（人类主体的）整秒 auth_time，机器主体绝不携带 auth_time。
///
/// fixture 形状对齐真实消费链：人类主体经 fleet-admin-web 形态的机密客户端请求
/// fleet.approve（scope 实体绑定 fleet-api 资源 → 令牌 aud 含 fleet-api），由 fleet-api
/// 形态的内省方读取。OpenIddict 的内省声明披露（AttachApplicationClaims）要求「内省方
/// 是令牌 audience 且非 public 客户端」，因此人类 fixture 必须带 fleet scope——这也是
/// 生产上 portal（public、无 fleet scope）令牌不经 fleet-api 内省的原因。
/// 契约正本：元仓 docs/contracts/fleet-lifecycle-v2-proposal.md。
/// </summary>
public class FleetIntrospectionTests
{
    [PostgresFact]
    public async Task HumanCodeFlow_ActualIntrospection_ExposesAuthTimeAndHumanSubjectType()
    {
        await using var fixture = await FleetProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        var original = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        await fixture.LoginAsync(client);
        var token = await fixture.CodeExchangeAsync(client);

        var inspected = await fixture.IntrospectAsync(client, token.GetProperty("access_token").GetString()!);

        Assert.True(inspected.GetProperty("active").GetBoolean());
        Assert.Equal(PandaAuthClaims.SubjectTypes.Human, inspected.GetProperty(PandaAuthClaims.SubjectType).GetString());
        Assert.Equal(original, inspected.GetProperty(Claims.AuthenticationTime).GetInt64());
        Assert.False(inspected.TryGetProperty(LoginSessionService.AuthenticatedAtClaim, out _));
    }

    [PostgresFact]
    public async Task MachineClientCredentials_ActualIntrospection_DeclaresMachineWithoutAuthTime()
    {
        await using var fixture = await FleetProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = FleetProtocolFixture.IntrospectorClientId,
            ["client_secret"] = fixture.IntrospectorSecret,
            ["grant_type"] = GrantTypes.ClientCredentials,
            ["scope"] = "api",
        });
        using var response = await client.PostAsync("/connect/token", form);
        Assert.True(response.StatusCode == HttpStatusCode.OK);
        using var token = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        var inspected = await fixture.IntrospectAsync(client, token.RootElement.GetProperty("access_token").GetString()!);

        Assert.True(inspected.GetProperty("active").GetBoolean());
        Assert.Equal(PandaAuthClaims.SubjectTypes.Machine, inspected.GetProperty(PandaAuthClaims.SubjectType).GetString());
        Assert.False(inspected.TryGetProperty(Claims.AuthenticationTime, out _));
    }

    [PostgresFact]
    public async Task HumanRefresh_ActualIntrospection_PreservesOriginalAuthTime()
    {
        await using var fixture = await FleetProtocolFixture.CreateAsync();
        using var client = fixture.Browser();
        var original = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        await fixture.LoginAsync(client);
        var token = await fixture.CodeExchangeAsync(client);
        fixture.Clock.Advance(TimeSpan.FromMinutes(2));
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = FleetProtocolFixture.AdminClientId,
            ["client_secret"] = fixture.AdminSecret,
            ["grant_type"] = GrantTypes.RefreshToken,
            ["refresh_token"] = token.GetProperty("refresh_token").GetString()!,
        });
        using var response = await client.PostAsync("/connect/token", form);
        Assert.True(response.StatusCode == HttpStatusCode.OK);
        using var refreshed = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        var inspected = await fixture.IntrospectAsync(client, refreshed.RootElement.GetProperty("access_token").GetString()!);

        Assert.Equal(PandaAuthClaims.SubjectTypes.Human, inspected.GetProperty(PandaAuthClaims.SubjectType).GetString());
        Assert.Equal(original, inspected.GetProperty(Claims.AuthenticationTime).GetInt64());
    }

    private sealed class MutableClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddMinutes(-3).ToUnixTimeSeconds());
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan span) => _now += span;
    }

    private sealed class FleetProtocolFactory(string connection, MutableClock clock) : WebApplicationFactory<Program>
    {
        private readonly ProtocolHostContentRoot _root = new(connection, new Dictionary<string, string>
        {
            ["Auth:Issuer"] = "http://localhost", ["Auth:HttpsRequired"] = "false", ["Auth:Seed:Enabled"] = "false",
        });
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseContentRoot(_root.Path);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureTestServices(services =>
            {
                services.AddDataProtection().UseEphemeralDataProtectionProvider();
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
            });
        }
        protected override void Dispose(bool disposing) { base.Dispose(disposing); _root.Dispose(); }
    }

    private sealed class FleetProtocolFixture : IAsyncDisposable
    {
        internal const string AdminClientId = "fleet-admin-fixture";
        // 内省方 client_id 必须与 fleet scope 的资源绑定（aud）精确一致——OpenIddict
        // AttachApplicationClaims 以「调用者 ∈ 令牌 audience」为披露前提，生产即 fleet-api。
        internal const string IntrospectorClientId = PandaAuthScopes.FleetApi;
        private const string Verifier = "fleet-test-code-verifier-01234567890123456789012345678";
        private readonly string _connection;
        private readonly string _password = "Aa!9" + Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
        internal string AdminSecret { get; } = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        internal string IntrospectorSecret { get; } = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        internal MutableClock Clock { get; } = new();
        internal FleetProtocolFactory Factory { get; }

        private FleetProtocolFixture(string connection)
        {
            _connection = connection;
            Factory = new FleetProtocolFactory(connection, Clock);
        }

        internal static async Task<FleetProtocolFixture> CreateAsync()
        {
            var admin = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
            if (admin.Host != "127.0.0.1" || admin.Port != 43823 || admin.Database != "postgres")
                throw new InvalidOperationException("Auth protocol fixture requires the approved task loopback cluster/admin database.");
            var name = "panda_protocol_test_" + Guid.NewGuid().ToString("N");
            await using (var connection = new NpgsqlConnection(admin.ConnectionString))
            {
                await connection.OpenAsync();
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
                await create.ExecuteNonQueryAsync();
            }
            admin.Database = name;
            var fixture = new FleetProtocolFixture(admin.ConnectionString);
            try
            {
                await using (var db = fixture.Context()) await db.Database.MigrateAsync();
                await fixture.SeedAsync();
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        private async Task SeedAsync()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(_connection).UseOpenIddict());
            services.AddUserStore();
            services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            Assert.True((await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(
                new PandaUser { UserName = "fleet-time-user", Email = "fixture@example.test", EmailConfirmed = true }, _password)).Succeeded);
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            // fleet-admin-web 形态：机密客户端 + 授权码/刷新 + PKCE，请求 fleet.approve（经 scope
            // 实体的 fleet-api 资源绑定，令牌 aud 落到 fleet-api，fleet-api 才能完整内省）。
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = AdminClientId,
                ClientType = ClientTypes.Confidential,
                ClientSecret = AdminSecret,
                ConsentType = ConsentTypes.Implicit,
                RedirectUris = { new Uri("http://localhost/callback") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code, Permissions.Scopes.Profile,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Permissions.Prefixes.Scope + PandaAuthScopes.FleetApprove,
                },
                Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            });
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = IntrospectorClientId,
                ClientType = ClientTypes.Confidential,
                ClientSecret = IntrospectorSecret,
                Permissions =
                {
                    Permissions.Endpoints.Token, Permissions.Endpoints.Introspection,
                    Permissions.GrantTypes.ClientCredentials, Permissions.Prefixes.Scope + "api",
                },
            });
            var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = PandaAuthScopes.FleetApprove, Resources = { PandaAuthScopes.FleetApi },
            });
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "api", Resources = { IntrospectorClientId },
            });
        }

        internal HttpClient Browser(bool handleCookies = true)
            => Factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = handleCookies });

        private static string AuthorizeUrl => "/connect/authorize?client_id=" + AdminClientId +
            "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code" +
            "&scope=openid%20profile%20offline_access%20" + PandaAuthScopes.FleetApprove +
            "&state=fleet-time-state&nonce=fleet-time-nonce" +
            "&code_challenge_method=S256&code_challenge=" +
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));

        internal async Task LoginAsync(HttpClient client)
        {
            var response = await client.GetAsync(AuthorizeUrl);
            Assert.True(response.StatusCode == HttpStatusCode.Redirect);
            var page = await client.GetAsync(response.Headers.Location!.PathAndQuery);
            var hidden = Regex.Match(await page.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
            Assert.True(hidden.Success);
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = WebUtility.HtmlDecode(hidden.Groups[1].Value),
                ["UserName"] = "fleet-time-user", ["Password"] = _password, ["ReturnUrl"] = AuthorizeUrl,
            });
            var login = await client.PostAsync("/account/login", form);
            Assert.True(login.StatusCode == HttpStatusCode.Redirect);
        }

        internal async Task<JsonElement> CodeExchangeAsync(HttpClient client)
        {
            var authorization = await client.GetAsync(AuthorizeUrl);
            Assert.True(authorization.StatusCode == HttpStatusCode.Redirect);
            var callback = authorization.Headers.Location!;
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(callback.Query);
            Assert.True(query["state"] == "fleet-time-state");
            Assert.True(query.ContainsKey("code"));
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = AdminClientId, ["client_secret"] = AdminSecret,
                ["grant_type"] = GrantTypes.AuthorizationCode, ["code"] = query["code"].ToString(),
                ["redirect_uri"] = "http://localhost/callback", ["code_verifier"] = Verifier,
            });
            using var response = await client.PostAsync("/connect/token", form);
            Assert.True(response.StatusCode == HttpStatusCode.OK);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.Clone();
        }

        internal async Task<JsonElement> IntrospectAsync(HttpClient client, string accessToken)
        {
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = IntrospectorClientId, ["client_secret"] = IntrospectorSecret, ["token"] = accessToken,
            });
            using var inspected = await client.PostAsync("/connect/introspect", form);
            Assert.True(inspected.StatusCode == HttpStatusCode.OK);
            using var json = JsonDocument.Parse(await inspected.Content.ReadAsStringAsync());
            return json.RootElement.Clone();
        }

        private PandaAuthDbContext Context() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(_connection).UseOpenIddict().Options);

        public async ValueTask DisposeAsync()
        {
            await Factory.DisposeAsync();
            var builder = new NpgsqlConnectionStringBuilder(_connection);
            if (builder.Host != "127.0.0.1" || builder.Port != 43823 ||
                builder.Database is null || !Regex.IsMatch(builder.Database, "^panda_protocol_test_[0-9a-f]{32}$", RegexOptions.CultureInvariant))
                throw new InvalidOperationException("Refusing cleanup outside this task-owned Auth database.");
            await using var db = Context();
            await db.Database.EnsureDeletedAsync();
        }
    }
}
