using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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

/// <summary>
/// Management API e2e（M0 S5）：隔离 PostgreSQL + 真实应用宿主的令牌化越权矩阵。
/// 覆盖：scope+audience 正向流（零凭据投影）、无 scope 拒绝、跨资源令牌拒绝（audience 门禁）、
/// 交互式客户端请求管理 scope 被拒（Auth0 教训的服务端印证）、吊销后 401、
/// 删除持久化+审计（EF InMemory 用例的 PG 补偿）、部署面开关关闭时路由不存在（404）。
/// </summary>
public sealed class ManagementApiE2eTests
{
    private const string MgmtSecret = "mgmt-api-e2e-secret";

    [PostgresFact]
    public async Task MgmtToken_CanCallUsersEndpoint_AndReceivesZeroCredentialProjection()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.SeedAsync();
        await using var factory = new MgmtFactory(database.ConnectionString, mgmtEnabled: true);
        using var client = factory.CreateClient();

        var token = await GetTokenAsync(client, PandaAuthMgmtApi.UsersReadScope);
        using var request = new HttpRequestMessage(HttpMethod.Get, PandaAuthMgmtApi.UsersRoute);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"users list returned {(int)response.StatusCode}: {body}");

        using var json = JsonDocument.Parse(body);
        Assert.True(json.RootElement.GetProperty("total").GetInt32() >= 1);
        var item = json.RootElement.GetProperty("items")[0];
        // 投影契约：只允许六个安全字段，凭据/安全戳字段永不出现。
        var allowed = new[] { "id", "userName", "email", "nickname", "status", "createdAt" };
        Assert.Subset(allowed.ToHashSet(), item.EnumerateObject().Select(property => property.Name).ToHashSet());
    }

    [PostgresFact]
    public async Task TokenWithoutMgmtScope_IsForbidden()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.SeedAsync();
        await using var factory = new MgmtFactory(database.ConnectionString, mgmtEnabled: true);
        using var client = factory.CreateClient();

        // 不带 scope 的 M2M 令牌：无 audience 无 scope，双条件门禁必拒。
        var token = await GetTokenAsync(client, scope: null);
        using var request = new HttpRequestMessage(HttpMethod.Get, PandaAuthMgmtApi.UsersRoute);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.SendAsync(request);
        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [PostgresFact]
    public async Task ForeignResourceToken_IsForbidden_OnManagementEndpoints()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.SeedAsync();
        await using var factory = new MgmtFactory(database.ConnectionString, mgmtEnabled: true);
        using var client = factory.CreateClient();

        // fleet-api 令牌带 fleet-api audience——scope 合法但 audience 不对，防跨资源重放。
        var token = await GetForeignResourceTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Get, PandaAuthMgmtApi.UsersRoute);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [PostgresFact]
    public async Task InteractiveClient_RequestingMgmtScope_IsRejected()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.SeedAsync();
        await using var factory = new MgmtFactory(database.ConnectionString, mgmtEnabled: true);
        using var client = factory.CreateClient();

        // 交互式应用客户端（无管理 scope 权限）请求管理 scope：令牌端点直接 invalid_scope，
        // 这是「业务客户端凭证不得意外获得管理权」的服务端印证（Auth0 组织级 M2M 教训）。
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "web-app",
            ["client_secret"] = "web-app-e2e-secret",
            ["grant_type"] = "client_credentials",
            ["scope"] = PandaAuthMgmtApi.UsersReadScope,
        });
        var response = await client.PostAsync("/connect/token", form);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(body);
        var error = json.RootElement.GetProperty("error").GetString();
        var description = json.RootElement.TryGetProperty("error_description", out var descriptionProperty)
            ? descriptionProperty.GetString()
            : null;
        // OpenIddict 7 对 scope 权限缺失返回 invalid_request（描述固定含 "not allowed to use the specified scope"），
        // 而非 RFC 6749 的 invalid_scope——钉住实际行为并留注释。
        Assert.True(
            description is not null && description.Contains("not allowed to use the specified scope", StringComparison.Ordinal),
            $"expected scope-permission rejection, got {error}: {description}");
    }

    [PostgresFact]
    public async Task RevokedMgmtToken_IsRejected()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.SeedAsync();
        await using var factory = new MgmtFactory(database.ConnectionString, mgmtEnabled: true);
        using var client = factory.CreateClient();

        var token = await GetTokenAsync(client, PandaAuthMgmtApi.UsersReadScope);

        using var revokeForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = "mgmt-api",
            ["client_secret"] = MgmtSecret,
        });
        var revoked = await client.PostAsync("/connect/revoke", revokeForm);
        Assert.True(revoked.IsSuccessStatusCode, $"revoke returned {(int)revoked.StatusCode}");

        using var request = new HttpRequestMessage(HttpMethod.Get, PandaAuthMgmtApi.UsersRoute);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.SendAsync(request);

        // 在线 token-entry validation：吊销后原令牌立即失效（401），不是等过期。
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgresFact]
    public async Task DeleteClient_PersistsAndAudits_OnPostgres()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.SeedAsync();
        await using var factory = new MgmtFactory(database.ConnectionString, mgmtEnabled: true);
        using var client = factory.CreateClient();

        // CRUD 动线同时涉及 write（创建/删除）与 read（详情确认）端点：令牌一次携带两个 scope。
        var writeToken = await GetTokenAsync(
            client, $"{PandaAuthMgmtApi.ClientsWriteScope} {PandaAuthMgmtApi.ClientsReadScope}");

        using var createForm = JsonContent.Create(new
        {
            displayName = "e2e 客户端",
            clientType = "confidential",
            redirectUris = new[] { "https://app.example.com/callback" },
        });
        using var createRequest = new HttpRequestMessage(HttpMethod.Post, PandaAuthMgmtApi.ClientsRoute)
        {
            Content = createForm,
        };
        createRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", writeToken);
        var created = await client.SendAsync(createRequest);
        var createdBody = await created.Content.ReadAsStringAsync();
        Assert.True(created.IsSuccessStatusCode, $"create returned {(int)created.StatusCode}: {createdBody}");
        using var createdJson = JsonDocument.Parse(createdBody);
        var clientId = createdJson.RootElement.GetProperty("client").GetProperty("clientId").GetString()!;
        Assert.False(string.IsNullOrWhiteSpace(
            createdJson.RootElement.GetProperty("generatedSecret").GetString()));

        using var deleteRequest = new HttpRequestMessage(HttpMethod.Delete, $"{PandaAuthMgmtApi.ClientsRoute}/{clientId}");
        deleteRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", writeToken);
        var deleted = await client.SendAsync(deleteRequest);
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        // 删除持久化（InMemory 用例的 PG 补偿）：详情 404 + 审计行在库。
        using var detailRequest = new HttpRequestMessage(HttpMethod.Get, $"{PandaAuthMgmtApi.ClientsRoute}/{clientId}");
        detailRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", writeToken);
        Assert.Equal(HttpStatusCode.NotFound, (await client.SendAsync(detailRequest)).StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var entry = await dbContext.AdminAuditLogs.SingleAsync(log => log.Action == "mgmt.client.delete");
        Assert.Equal(clientId, entry.TargetId);
        Assert.Equal("mgmt-api", entry.ActorUserId);
    }

    [PostgresFact]
    public async Task ManagementRoutes_AreAbsent_WhenDisabled()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.SeedAsync();
        // 开关默认关闭：管理控制器整体不进路由模型，未认证请求也是 404（对外等效不存在）。
        await using var factory = new MgmtFactory(database.ConnectionString, mgmtEnabled: false);
        using var client = factory.CreateClient();

        var response = await client.GetAsync(PandaAuthMgmtApi.UsersRoute);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static async Task<string> GetTokenAsync(HttpClient client, string? scope)
    {
        var form = new Dictionary<string, string>
        {
            ["client_id"] = "mgmt-api",
            ["client_secret"] = MgmtSecret,
            ["grant_type"] = "client_credentials",
        };
        if (scope is not null)
        {
            form["scope"] = scope;
        }

        var issued = await client.PostAsync("/connect/token", new FormUrlEncodedContent(form));
        var body = await issued.Content.ReadAsStringAsync();
        Assert.True(issued.IsSuccessStatusCode, $"mgmt token request returned {(int)issued.StatusCode}: {body}");
        var token = await issued.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.True(!string.IsNullOrWhiteSpace(token?.AccessToken), $"mgmt token response 200 without access_token: {body}");
        return token!.AccessToken!;
    }

    private static async Task<string> GetForeignResourceTokenAsync(HttpClient client)
    {
        var issued = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "fleet-api",
            ["client_secret"] = "fleet-api-e2e-secret",
            ["grant_type"] = "client_credentials",
            ["scope"] = "fleet.read",
        }));
        var body = await issued.Content.ReadAsStringAsync();
        Assert.True(issued.IsSuccessStatusCode, $"fleet token request returned {(int)issued.StatusCode}: {body}");
        var token = await issued.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.False(string.IsNullOrWhiteSpace(token?.AccessToken));
        return token!.AccessToken!;
    }

    // OAuth 响应是 snake_case：必须显式 JsonPropertyName（大小写不敏感不处理下划线）。
    private sealed record TokenResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string? AccessToken);

    private sealed class MgmtFactory(string connectionString, bool mgmtEnabled) : WebApplicationFactory<Program>
    {
        private readonly ProtocolHostContentRoot _root = new(connectionString, new Dictionary<string, string>
        {
            ["Auth:Issuer"] = "http://localhost/", ["Auth:HttpsRequired"] = "false", ["Auth:Seed:Enabled"] = "false",
            ["Auth:Mgmt:Enabled"] = mgmtEnabled ? "true" : "false", ["Logging:LogLevel:Default"] = "Warning",
            ["Logging:LogLevel:Microsoft.AspNetCore"] = "Warning", ["Logging:LogLevel:OpenIddict"] = mgmtEnabled ? "Debug" : "Warning",
        });
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseContentRoot(_root.Path);
        }
        protected override void Dispose(bool disposing) { base.Dispose(disposing); _root.Dispose(); }
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
            var name = "panda_mgmt_e2e_" + Guid.NewGuid().ToString("N");
            await using var command = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
            await command.ExecuteNonQueryAsync();
            admin.Database = name;
            return new TestDatabase(admin.ConnectionString);
        }

        /// <summary>
        /// 种子走真实 DbSeeder（mgmt 开关开启）——作用域实体、资源绑定与 mgmt-api 客户端
        /// 与生产同一条代码路径；再补一个用户与一个无管理 scope 的交互式客户端作反向用例。
        /// </summary>
        public async Task SeedAsync()
        {
            // 先迁移建表，再跑真实 DbSeeder 与用例数据。
            await using (var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
                .UseNpgsql(ConnectionString).UseOpenIddict().Options))
            {
                await db.Database.MigrateAsync();
            }

            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(ConnectionString).UseOpenIddict());
            services.AddUserStore();
            services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
            services.AddSingleton(Options.Create(new AuthOptions
            {
                Seed = new SeedOptions
                {
                    Enabled = true,
                    Admin = new AdminSeedOptions { Email = "e2e-admin@example.com", Password = string.Empty },
                    Me = new MeSeedOptions { Enabled = false },
                    AdminWeb = new AdminWebSeedOptions { Enabled = false },
                    Fleet = new FleetSeedOptions { Enabled = false },
                    Demo = new DemoSeedOptions { Enabled = false },
                    Mgmt = new MgmtSeedOptions { Enabled = true, ClientSecret = MgmtSecret },
                },
            }));
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            await DbSeeder.SeedAsync(scope.ServiceProvider);

            var userManager = scope.ServiceProvider.GetRequiredService<UserService>();
            var userResult = await userManager.CreateAsync(new PandaUser
            {
                UserName = "mgmt-e2e-user",
                Email = "mgmt-e2e-user@example.com",
                EmailConfirmed = true,
            }, "Strong!Pass123");
            Assert.True(userResult.Succeeded);

            // 交互式反向用例客户端：有 client_credentials 但没有任何管理 scope 权限。
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web-app",
                ClientType = ClientTypes.Confidential,
                ClientSecret = "web-app-e2e-secret",
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "交互式反向用例客户端",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + Scopes.OpenId,
                },
            });

            // fleet-api（跨资源重放用例）：audience=fleet-api 的合法令牌。
            var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "fleet.read",
                DisplayName = "fleet.read",
                Resources = { "fleet-api" },
            });
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "fleet-api",
                ClientType = ClientTypes.Confidential,
                ClientSecret = "fleet-api-e2e-secret",
                ConsentType = ConsentTypes.Implicit,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "fleet.read",
                },
            });
        }

        public async ValueTask DisposeAsync()
        {
            await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
                .UseNpgsql(ConnectionString).UseOpenIddict().Options);
            await db.Database.EnsureDeletedAsync();
        }
    }
}
