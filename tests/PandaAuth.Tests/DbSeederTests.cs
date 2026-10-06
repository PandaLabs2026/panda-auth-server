using PandaAuth.Server.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>Seeder 集成测试：EF InMemory + 真实 OpenIddict Core 管理器，验证播种开关与 me-web / admin-web / oasis-web upsert 行为。</summary>
public class DbSeederTests
{
    private const string MeRedirectUri = "https://auth.pandalabs.cn/me/callback/login/pandaauth";

    private const string MePostLogoutUri = "https://auth.pandalabs.cn/me/";

    private const string MeClientSecret = "me-web-test-secret";

    private const string AdminWebRedirectUri = "https://auth.pandalabs.cn/admin/callback/login/pandaauth";

    private const string AdminWebPostLogoutUri = "https://auth.pandalabs.cn/admin/callback/logout/pandaauth";

    private const string AdminWebClientSecret = "admin-web-test-secret";

    private const string OasisWebRedirectUri = "https://oasis.pandalabs.cn/signin-oidc";

    private const string OasisWebPostLogoutUri = "https://oasis.pandalabs.cn/";

    private const string OasisWebClientSecret = "oasis-web-test-secret";

    private const string FleetAdminWebRedirectUri = "https://fleet.appliket.com/admin/callback/pandaauth";

    private const string FleetAdminWebPostLogoutUri = "https://fleet.appliket.com/admin/callback/logout/pandaauth";

    private const string FleetAdminWebClientSecret = "fleet-admin-web-test-secret";

    // 密钥对账用例用的存量旧回调：刻意不用已退役域名，避免与域名退役检查的
    // 负断言夹具（`.cn` 命中数基线）重复计数。
    private const string LegacyRedirectUri = "http://localhost:9007/callback/login/pandaauth";

    private const string LegacyPostLogoutUri = "http://localhost:9007/";

    [Fact]
    public async Task SeedDisabled_DoesNotResolveSeedDependencies()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Options.Create(new AuthOptions
        {
            Seed = new SeedOptions { Enabled = false },
        }));

        await DbSeeder.SeedAsync(services.BuildServiceProvider());
    }

    [Fact]
    public async Task DemoDisabledByDefault_DoesNotCreateDemoClients()
    {
        var options = ValidOptions();

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("demo-public"));
        Assert.Null(await applications.FindByClientIdAsync("demo-web"));
        Assert.Null(await applications.FindByClientIdAsync("demo-service"));

        // 总开关开启时仅播种第一方客户端（me-web 与 admin-web），证明 Seeder 确实执行过。
        Assert.NotNull(await applications.FindByClientIdAsync("me-web"));
        Assert.NotNull(await applications.FindByClientIdAsync("admin-web"));
    }

    [Fact]
    public async Task DemoEnabledWithSecrets_CreatesClientsWithConfiguredSecrets()
    {
        var options = ValidOptions();
        options.Seed.Demo = new DemoSeedOptions
        {
            Enabled = true,
            WebSecret = "demo-web-test-secret",
            ServiceSecret = "demo-service-test-secret",
        };

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.NotNull(await applications.FindByClientIdAsync("demo-public"));
        Assert.NotNull(await applications.FindByClientIdAsync("demo-web"));
        Assert.NotNull(await applications.FindByClientIdAsync("demo-service"));

        // 密钥必须来自配置注入，旧源码固定密钥（*-secret-change-me）不得再通过校验。
        var web = await applications.FindByClientIdAsync("demo-web");
        Assert.NotNull(web);
        Assert.True(await applications.ValidateClientSecretAsync(web, "demo-web-test-secret"));
        Assert.False(await applications.ValidateClientSecretAsync(web, "demo-web-secret-change-me"));

        var service = await applications.FindByClientIdAsync("demo-service");
        Assert.NotNull(service);
        Assert.True(await applications.ValidateClientSecretAsync(service, "demo-service-test-secret"));
        Assert.False(await applications.ValidateClientSecretAsync(service, "demo-service-secret-change-me"));
    }

    [Fact]
    public async Task FleetEnabled_CreatesConfidentialClientWithPlatformScopes()
    {
        var options = ValidOptions();
        options.Seed.Fleet = new FleetSeedOptions
        {
            Enabled = true,
            ClientSecret = "fleet-api-test-secret",
        };

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var fleet = await applications.FindByClientIdAsync("fleet-api");
        Assert.NotNull(fleet);
        Assert.True(await applications.ValidateClientSecretAsync(fleet, "fleet-api-test-secret"));
        Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(fleet));
        Assert.True(await applications.HasPermissionAsync(fleet, Permissions.GrantTypes.ClientCredentials));
        Assert.True(await applications.HasPermissionAsync(fleet, Permissions.Prefixes.Scope + "fleet.read"));
        Assert.True(await applications.HasPermissionAsync(fleet, Permissions.Prefixes.Scope + "fleet.allocate"));
        Assert.True(await applications.HasPermissionAsync(fleet, Permissions.Prefixes.Scope + "fleet.apply"));
        Assert.True(await applications.HasPermissionAsync(fleet, Permissions.Prefixes.Scope + "fleet.server.manage"));
        Assert.False(await applications.HasPermissionAsync(fleet, Permissions.Endpoints.Authorization));

        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        Assert.NotNull(await scopes.FindByNameAsync("fleet.read"));
        Assert.NotNull(await scopes.FindByNameAsync("fleet.allocate"));
        Assert.NotNull(await scopes.FindByNameAsync("fleet.apply"));
        Assert.NotNull(await scopes.FindByNameAsync("fleet.server.manage"));
    }

    [Fact]
    public async Task FleetEnabledWithoutSecret_FailsClosed()
    {
        var options = ValidOptions();
        options.Seed.Fleet = new FleetSeedOptions { Enabled = true };

        using var provider = BuildProvider(options);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));

        Assert.Contains("Auth:Seed:Fleet:ClientSecret", exception.Message);
    }

    [Fact]
    public async Task FleetAdminWebDisabledByDefault_DoesNotCreateClient()
    {
        // fleet-admin-web 与 OasisWeb 同策略：非 PandaAuth 自带面板，默认关闭，
        // 未显式开启时任何部署（含共享实例）都不得出现该客户端。
        var options = ValidOptions();

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("fleet-admin-web"));
    }

    [Fact]
    public async Task FleetAdminWebEnabled_CreatesConfidentialClientWithFleetScopes()
    {
        var options = ValidOptions();
        options.Seed.FleetAdminWeb = new FleetAdminWebSeedOptions
        {
            Enabled = true,
            ClientSecret = FleetAdminWebClientSecret,
            RedirectUris = [FleetAdminWebRedirectUri],
            PostLogoutRedirectUris = [FleetAdminWebPostLogoutUri],
        };

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var fleetAdmin = await applications.FindByClientIdAsync("fleet-admin-web");
        Assert.NotNull(fleetAdmin);
        Assert.True(await applications.ValidateClientSecretAsync(fleetAdmin, FleetAdminWebClientSecret));
        Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(fleetAdmin));
        Assert.Contains(FleetAdminWebRedirectUri, await applications.GetRedirectUrisAsync(fleetAdmin));
        Assert.Contains(FleetAdminWebPostLogoutUri, await applications.GetPostLogoutRedirectUrisAsync(fleetAdmin));
        // 第一方 Web 基础面：授权码 + 刷新令牌 + PKCE + 登出/吊销端点。
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.GrantTypes.AuthorizationCode));
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.GrantTypes.RefreshToken));
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.Endpoints.EndSession));
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.Endpoints.Revocation));
        // fleet.* 委托作用域：管理台代表操作者调 Fleet Server，token 受众经 scope Resources 落到 fleet-api。
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.Prefixes.Scope + "fleet.read"));
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.Prefixes.Scope + "fleet.allocate"));
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.Prefixes.Scope + "fleet.apply"));
        Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.Prefixes.Scope + "fleet.server.manage"));
    }

    [Fact]
    public async Task FleetEnabled_RegistersAllSevenControlPlaneScopesAndGrantsThemToFleetApi()
    {
        var options = ValidOptions();
        options.Seed.Fleet = new FleetSeedOptions
        {
            Enabled = true,
            ClientSecret = "fleet-api-test-secret",
        };

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        foreach (var name in PandaAuthScopes.FleetAll)
        {
            var scope = await scopes.FindByNameAsync(name);
            Assert.NotNull(scope);
            Assert.Contains(PandaAuthScopes.FleetApi, await scopes.GetResourcesAsync(scope));
        }

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var fleet = await applications.FindByClientIdAsync("fleet-api");
        Assert.NotNull(fleet);
        foreach (var name in PandaAuthScopes.FleetAll)
            Assert.True(await applications.HasPermissionAsync(fleet, Permissions.Prefixes.Scope + name),
                $"fleet-api 缺少控制面 scope 授权：{name}");
    }

    [Fact]
    public async Task FleetAdminWebEnabled_GrantsAllSevenControlPlaneScopes()
    {
        var options = ValidOptions();
        options.Seed.FleetAdminWeb = new FleetAdminWebSeedOptions
        {
            Enabled = true,
            ClientSecret = FleetAdminWebClientSecret,
            RedirectUris = [FleetAdminWebRedirectUri],
            PostLogoutRedirectUris = [FleetAdminWebPostLogoutUri],
        };

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var fleetAdmin = await applications.FindByClientIdAsync("fleet-admin-web");
        Assert.NotNull(fleetAdmin);
        foreach (var name in PandaAuthScopes.FleetAll)
            Assert.True(await applications.HasPermissionAsync(fleetAdmin, Permissions.Prefixes.Scope + name),
                $"fleet-admin-web 缺少控制面 scope 授权：{name}");
    }

    [Fact]
    public async Task MgmtEnabled_CreatesConfidentialClientWithMgmtScopes()
    {
        var options = ValidOptions();
        options.Seed.Mgmt = new MgmtSeedOptions
        {
            Enabled = true,
            ClientSecret = "mgmt-api-test-secret",
        };

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var mgmt = await applications.FindByClientIdAsync("mgmt-api");
        Assert.NotNull(mgmt);
        Assert.True(await applications.ValidateClientSecretAsync(mgmt, "mgmt-api-test-secret"));
        Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(mgmt));
        Assert.True(await applications.HasPermissionAsync(mgmt, Permissions.GrantTypes.ClientCredentials));
        Assert.True(await applications.HasPermissionAsync(mgmt, Permissions.Prefixes.Scope + "mgmt.clients.read"));
        Assert.True(await applications.HasPermissionAsync(mgmt, Permissions.Prefixes.Scope + "mgmt.clients.write"));
        Assert.True(await applications.HasPermissionAsync(mgmt, Permissions.Prefixes.Scope + "mgmt.users.read"));
        Assert.False(await applications.HasPermissionAsync(mgmt, Permissions.Endpoints.Authorization));

        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        var usersRead = await scopes.FindByNameAsync("mgmt.users.read");
        Assert.NotNull(usersRead);
        Assert.Contains("panda-mgmt-api", await scopes.GetResourcesAsync(usersRead));
    }

    [Fact]
    public async Task MgmtEnabledWithoutSecret_FailsClosed()
    {
        var options = ValidOptions();
        options.Seed.Mgmt = new MgmtSeedOptions { Enabled = true };

        using var provider = BuildProvider(options);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));

        Assert.Contains("Auth:Seed:Mgmt:ClientSecret", exception.Message);
    }

    [Fact]
    public async Task DemoEnabledWithoutWebSecret_ThrowsBeforeCreatingClients()
    {
        var options = ValidOptions();
        options.Seed.Demo = new DemoSeedOptions
        {
            Enabled = true,
            WebSecret = "",
            ServiceSecret = "demo-service-test-secret",
        };

        using var provider = BuildProvider(options);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DbSeeder.SeedAsync(provider));

        Assert.Contains("Auth:Seed:Demo:WebSecret", exception.Message);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("demo-public"));
        Assert.Null(await applications.FindByClientIdAsync("demo-web"));
        Assert.Null(await applications.FindByClientIdAsync("demo-service"));
    }

    [Fact]
    public async Task DemoEnabledWithoutServiceSecret_ThrowsBeforeCreatingClients()
    {
        var options = ValidOptions();
        options.Seed.Demo = new DemoSeedOptions
        {
            Enabled = true,
            WebSecret = "demo-web-test-secret",
            ServiceSecret = "",
        };

        using var provider = BuildProvider(options);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DbSeeder.SeedAsync(provider));

        Assert.Contains("Auth:Seed:Demo:ServiceSecret", exception.Message);
    }

    [Fact]
    public async Task MeWebExists_ReplacesWhitelistFromConfigAndKeepsSecret()
    {
        // 存量事故现场：库内 me-web 仍登记 .cn 回调；配置改为 .cc 后由 upsert 整体订正。
        // 库内密钥与配置一致（漂移场景由 MeWebExists_ClientSecretDriftIsReconciledAndOldSecretRejected 覆盖），
        // 这里验证的是白名单写回不会顺手把已正确的密钥哈希改掉。
        var options = ValidOptions();
        options.Seed.Me.RedirectUris =
            [MeRedirectUri, "http://localhost:9007/me/callback/login/pandaauth"];
        options.Seed.Me.PostLogoutRedirectUris = [MePostLogoutUri];

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "me-web",
            "PandaAuth 账户中心",
            redirectUris:
            [
                "https://auth.pandalabs.cn/me/callback/login/pandaauth",
                "http://localhost:9007/callback/login/pandaauth",
            ],
            postLogoutUris: ["https://auth.pandalabs.cn/me/"],
            clientSecret: MeClientSecret);

        await DbSeeder.SeedAsync(provider);

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);

        // 回调白名单被配置值整体替换（.cn 旧值不残留）。
        var redirectUris = await applications.GetRedirectUrisAsync(meWeb);
        Assert.Equal(
            new[] { MeRedirectUri, "http://localhost:9007/me/callback/login/pandaauth" }.OrderBy(x => x),
            redirectUris.OrderBy(x => x));

        var postLogoutUris = await applications.GetPostLogoutRedirectUrisAsync(meWeb);
        Assert.Equal(new[] { MePostLogoutUri }, postLogoutUris.OrderBy(x => x));

        // 密钥无需对账（已与配置一致）→ 保持可用；其余字段（客户端类型、权限）不受影响。
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, MeClientSecret));
        Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(meWeb));
        Assert.True(await applications.HasPermissionAsync(meWeb, Permissions.Endpoints.Token));
    }

    [Fact]
    public async Task MeWebExists_ClientSecretDriftIsReconciledAndOldSecretRejected()
    {
        // 两端漂移现场：库内 me-web 密钥仍是 A，服务器 env 已改成 B；Seeder 对账后应以 B 为准。
        const string configuredSecret = "me-web-configured-secret";
        var options = ValidOptions();
        options.Seed.Me.ClientSecret = configuredSecret;

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "me-web",
            "PandaAuth 账户中心",
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "me-web-original-secret");

        await DbSeeder.SeedAsync(provider);

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);

        Assert.True(await applications.ValidateClientSecretAsync(meWeb, configuredSecret));
        Assert.False(await applications.ValidateClientSecretAsync(meWeb, "me-web-original-secret"));

        // 密钥必须是以哈希形态落库，而不是把配置明文直接写进列里
        // （descriptor.ClientSecret + PopulateAsync 写回正是后者，会让新旧密钥双双校验失败）。
        Assert.NotEqual(configuredSecret, await ReadStoredClientSecretAsync(provider, "me-web"));

        // 顺带确认同一轮里白名单订正没有被密钥改写带坏。
        var redirectUris = await applications.GetRedirectUrisAsync(meWeb);
        Assert.Equal(new[] { MeRedirectUri }, redirectUris.OrderBy(x => x));
    }

    [Fact]
    public async Task MeWebExists_ClientSecretReconciliationIsIdempotent()
    {
        // 幂等：第二次 migrate 时密钥已能通过校验，不得再重写哈希列（否则每次启动都会换盐）。
        const string configuredSecret = "me-web-configured-secret";
        var options = ValidOptions();
        options.Seed.Me.ClientSecret = configuredSecret;

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "me-web",
            "PandaAuth 账户中心",
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "me-web-original-secret");

        await DbSeeder.SeedAsync(provider);
        var afterFirstRun = await ReadStoredClientSecretAsync(provider, "me-web");

        await DbSeeder.SeedAsync(provider);
        var afterSecondRun = await ReadStoredClientSecretAsync(provider, "me-web");

        Assert.Equal(afterFirstRun, afterSecondRun);

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, configuredSecret));
    }

    [Fact]
    public async Task MeWebExists_EmptyConfiguredSecret_KeepsExistingSecretWithoutThrowing()
    {
        // 已存在的部署 + 临时未配密钥：不抛异常（否则 migrate 直接失败），也不动库内密钥。
        var options = ValidOptions();
        options.Seed.Me.ClientSecret = "";
        options.Seed.Me.RedirectUris =
            [MeRedirectUri, "http://localhost:9007/me/callback/login/pandaauth"];
        options.Seed.Me.PostLogoutRedirectUris = [MePostLogoutUri];

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "me-web",
            "PandaAuth 账户中心",
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "me-web-original-secret");
        var hashBefore = await ReadStoredClientSecretAsync(provider, "me-web");

        await DbSeeder.SeedAsync(provider);

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, "me-web-original-secret"));
        Assert.Equal(hashBefore, await ReadStoredClientSecretAsync(provider, "me-web"));

        // 白名单订正照常生效，证明这一轮 Seeder 确实跑到了更新路径。
        var redirectUris = await applications.GetRedirectUrisAsync(meWeb);
        Assert.Equal(
            new[] { MeRedirectUri, "http://localhost:9007/me/callback/login/pandaauth" }.OrderBy(x => x),
            redirectUris.OrderBy(x => x));
    }

    [Fact]
    public async Task MeWebExists_OnlySecretConfigured_StillReconcilesSecret()
    {
        // 只配密钥、不配白名单：旧实现的早退分支会在这里跳掉对账，重构后必须仍然订正密钥。
        const string configuredSecret = "me-web-configured-secret";
        var options = ValidOptions();
        options.Seed.Me.ClientSecret = configuredSecret;
        options.Seed.Me.RedirectUris = [];
        options.Seed.Me.PostLogoutRedirectUris = [];

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "me-web",
            "PandaAuth 账户中心",
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "me-web-original-secret");

        await DbSeeder.SeedAsync(provider);

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, configuredSecret));
        Assert.False(await applications.ValidateClientSecretAsync(meWeb, "me-web-original-secret"));

        // 未配白名单 → 存量白名单原样保留。
        var redirectUris = await applications.GetRedirectUrisAsync(meWeb);
        Assert.Equal(new[] { LegacyRedirectUri }, redirectUris.OrderBy(x => x));
        var postLogoutUris = await applications.GetPostLogoutRedirectUrisAsync(meWeb);
        Assert.Equal(new[] { LegacyPostLogoutUri }, postLogoutUris.OrderBy(x => x));
    }

    [Fact]
    public async Task MeWebMissing_CreatedWithWhitelistFromConfig()
    {
        var options = ValidOptions();

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);

        var redirectUris = await applications.GetRedirectUrisAsync(meWeb);
        Assert.Equal(new[] { MeRedirectUri }, redirectUris.OrderBy(x => x));

        var postLogoutUris = await applications.GetPostLogoutRedirectUrisAsync(meWeb);
        Assert.Equal(new[] { MePostLogoutUri }, postLogoutUris.OrderBy(x => x));

        Assert.True(await applications.ValidateClientSecretAsync(meWeb, MeClientSecret));
    }

    [Fact]
    public async Task MeWebMissingWithoutRedirectUris_Throws()
    {
        var options = ValidOptions();
        options.Seed.Me.RedirectUris = [];

        using var provider = BuildProvider(options);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DbSeeder.SeedAsync(provider));

        Assert.Contains("Auth:Seed:Me:RedirectUris", exception.Message);
    }

    [Fact]
    public void MeSeedDefaultPostLogoutUris_UseDedicatedLogoutPath()
    {
        // 种子默认值即生产事实：未显式注入 Auth__Seed__Me__PostLogoutRedirectUris* 的部署，
        // migrate 直接把该默认值登记进 me-web 白名单。me 客户端自 de78b73 起硬编码回跳
        // me/callback/logout/pandaauth，默认值若为裸根 /me/，end-session 会因
        // post_logout_redirect_uri 全等失配被拒。与 deploy/verify-me-callback.sh 的
        // ②④⑥⑧ 与条数不变式同口径，仓内先行卡住漂移。
        var serverDirectory = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "PandaAuth.Server"));

        var options = new ConfigurationBuilder()
            .SetBasePath(serverDirectory)
            .AddJsonFile("appsettings.json")
            .Build()
            .GetSection(AuthOptions.SectionName).Get<AuthOptions>()
            ?? throw new InvalidOperationException("未能从 appsettings 绑定 AuthOptions。");

        // 登录回调维持不动（本修复只动 post-logout）。
        Assert.Equal(
        [
            "https://auth.pandalabs.cn/me/callback/login/pandaauth",
            "http://localhost:9007/me/callback/login/pandaauth",
        ], options.Seed.Me.RedirectUris);
        Assert.Equal(
        [
            "https://auth.pandalabs.cn/me/callback/logout/pandaauth",
            "http://localhost:9007/me/callback/logout/pandaauth",
        ], options.Seed.Me.PostLogoutRedirectUris);
    }

    [Fact]
    public async Task DevelopmentConfig_SeedsFreshDatabaseWithoutThrowing()
    {
        // 回归：全新空库 + Development 配置启动即播种不抛异常（旧结构缺 MeClientSecret 会硬失败）。
        var serverDirectory = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "PandaAuth.Server"));

        var configuration = new ConfigurationBuilder()
            .SetBasePath(serverDirectory)
            .AddJsonFile("appsettings.json")
            .AddJsonFile("appsettings.Development.json")
            .Build();

        var options = configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>()
            ?? throw new InvalidOperationException("未能从 appsettings 绑定 AuthOptions。");

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("demo-public"));
        Assert.Null(await applications.FindByClientIdAsync("demo-web"));
        Assert.Null(await applications.FindByClientIdAsync("demo-service"));

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);
        Assert.Contains("http://localhost:9007/me/callback/login/pandaauth",
            await applications.GetRedirectUrisAsync(meWeb));
        // 与 admin-web 同规：me 登出回跳必须是专用路径（me 客户端硬编码 callback/logout/pandaauth），
        // 裸根 /me/ 会被 end-session 以 post_logout_redirect_uri 失配拒绝。
        Assert.Contains("http://localhost:9007/me/callback/logout/pandaauth",
            await applications.GetPostLogoutRedirectUrisAsync(meWeb));
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, "me-web-dev-secret"));

        var adminWeb = await applications.FindByClientIdAsync("admin-web");
        Assert.NotNull(adminWeb);
        Assert.Contains("http://localhost:9006/admin/callback/login/pandaauth",
            await applications.GetRedirectUrisAsync(adminWeb));
        // 登出回跳必须是专用路径（/admin/callback/logout/...），不得复用 SPA 根 /admin/：
        // PostLogoutRedirectUri 与 SPA 根重合会让 OpenIddict 客户端拦截每次首页访问（空 state → 400）。
        Assert.Contains("http://localhost:9006/admin/callback/logout/pandaauth",
            await applications.GetPostLogoutRedirectUrisAsync(adminWeb));
        Assert.True(await applications.ValidateClientSecretAsync(adminWeb, "admin-web-dev-secret"));

        // Development 下 OasisWeb 显式开启（appsettings.json 的默认是 false）：
        // 本地开发要能直接用 localhost:5000 回调起完整握手。
        var oasisWeb = await applications.FindByClientIdAsync("oasis-web");
        Assert.NotNull(oasisWeb);
        Assert.Contains("http://localhost:5000/signin-oidc",
            await applications.GetRedirectUrisAsync(oasisWeb));
        Assert.True(await applications.ValidateClientSecretAsync(oasisWeb, "oasis-web-dev-secret"));
        var userManager = provider.GetRequiredService<UserService>();
        Assert.NotNull(await userManager.FindByNameAsync("admin@example.com"));
    }

    [Fact]
    public async Task MeDisabled_SkipsMeWebSeedAndUpsert()
    {
        // 预置 .cn 回调的存量 me-web；Me.Enabled=false 时既不播种也不订正。
        var options = ValidOptions();
        options.Seed.Me.Enabled = false;

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "me-web",
            "PandaAuth 账户中心",
            redirectUris: ["https://auth.pandalabs.cn/me/callback/login/pandaauth"],
            postLogoutUris: ["https://auth.pandalabs.cn/me/"],
            clientSecret: "me-web-original-secret");

        await DbSeeder.SeedAsync(provider);

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);

        var redirectUris = await applications.GetRedirectUrisAsync(meWeb);
        Assert.Equal(new[] { "https://auth.pandalabs.cn/me/callback/login/pandaauth" }, redirectUris.OrderBy(x => x));
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, "me-web-original-secret"));
    }

    // admin-web 与 me-web 共用 SeedFirstPartyWebApplicationAsync；方法级行为（白名单整体替换、
    // 密钥幂等对账、明文不得入库）已由上面 me-web 套件覆盖，这里只验证 admin-web 调用点的接线：
    // clientId / 配置键前缀 / 白名单取值正确，以及独立开关生效。
    // 存量旧回调一律用 localhost 值，不新增 .cn 命中（按文件计数基线卡总量）。

    [Fact]
    public async Task AdminWebMissing_CreatedWithWhitelistFromConfig()
    {
        var options = ValidOptions();

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var adminWeb = await applications.FindByClientIdAsync("admin-web");
        Assert.NotNull(adminWeb);

        var redirectUris = await applications.GetRedirectUrisAsync(adminWeb);
        Assert.Equal(new[] { AdminWebRedirectUri }, redirectUris.OrderBy(x => x));

        var postLogoutUris = await applications.GetPostLogoutRedirectUrisAsync(adminWeb);
        Assert.Equal(new[] { AdminWebPostLogoutUri }, postLogoutUris.OrderBy(x => x));

        Assert.True(await applications.ValidateClientSecretAsync(adminWeb, AdminWebClientSecret));
        Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(adminWeb));
        // 门禁依赖 roles scope：admin-web 注册必须带该 scope 权限。
        Assert.True(await applications.HasPermissionAsync(adminWeb, Permissions.Scopes.Roles));
    }

    [Fact]
    public async Task ReadyPandaAuthTenant_AddsTenantHostCallbacksToFirstPartyWhitelists()
    {
        var options = ValidOptions();
        options.TenantRouting.Bindings =
        [
            new TenantRouteBindingOptions
            {
                TenantId = "t0042",
                Product = TenantProduct.PandaAuth,
                State = TenantRouteState.Ready,
            },
        ];

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var meWeb = await applications.FindByClientIdAsync("me-web");
        var adminWeb = await applications.FindByClientIdAsync("admin-web");
        Assert.NotNull(meWeb);
        Assert.NotNull(adminWeb);

        Assert.Contains("https://t0042-auth.s001.pandalabs.cn/me/callback/login/pandaauth",
            await applications.GetRedirectUrisAsync(meWeb));
        Assert.Contains("https://t0042-auth.s001.pandalabs.cn/me/",
            await applications.GetPostLogoutRedirectUrisAsync(meWeb));
        Assert.Contains("https://t0042-auth.s001.pandalabs.cn/admin/callback/login/pandaauth",
            await applications.GetRedirectUrisAsync(adminWeb));
        Assert.Contains("https://t0042-auth.s001.pandalabs.cn/admin/",
            await applications.GetPostLogoutRedirectUrisAsync(adminWeb));
    }

    [Fact]
    public async Task SeededFirstPartyClients_AllCoveredByManagementReservedList()
    {
        // 防漂移锚点：全开关播种后，DbSeeder 实际落库的每个客户端都必须在第一方保留名单内
        // （Management API 对名单只读）。新增播种客户端而未登记 FirstPartyClients 会在此失败，
        // 而不是等自动化通道误伤种子对账时才暴露。
        var options = ValidOptions();
        options.Seed.OasisWeb = new OasisWebSeedOptions
        {
            Enabled = true,
            ClientSecret = OasisWebClientSecret,
            RedirectUris = [OasisWebRedirectUri],
            PostLogoutRedirectUris = [OasisWebPostLogoutUri],
        };
        options.Seed.FleetAdminWeb = new FleetAdminWebSeedOptions
        {
            Enabled = true,
            ClientSecret = FleetAdminWebClientSecret,
            RedirectUris = [FleetAdminWebRedirectUri],
            PostLogoutRedirectUris = [FleetAdminWebPostLogoutUri],
        };
        options.Seed.AsstWeb = new AsstWebSeedOptions
        {
            Enabled = true,
            ClientSecret = "asst-web-secret-0123456789abcdef",
            RedirectUris = ["https://asst.example.local/app/callback/pandaauth"],
            PostLogoutRedirectUris = ["https://asst.example.local/app/"],
        };
        options.Seed.AsstAdmin = new AsstAdminSeedOptions
        {
            Enabled = true,
            ClientSecret = "asst-admin-secret-0123456789abcd",
            RedirectUris = ["https://asst.example.local/admin/callback/pandaauth"],
            PostLogoutRedirectUris = ["https://asst.example.local/admin/"],
        };
        options.Seed.AsstMobile = new AsstMobileSeedOptions
        {
            Enabled = true,
            RedirectUris = ["https://t0042-asst.s001.pandalabs.cn/app/callback/mobile"],
            PostLogoutRedirectUris = ["https://t0042-asst.s001.pandalabs.cn/app/"],
        };
        options.Seed.AsstServer = new AsstServerSeedOptions
        {
            Enabled = true,
            ClientSecret = "asst-server-secret-0123456789abcdef",
        };
        options.Seed.Fleet = new FleetSeedOptions { Enabled = true, ClientSecret = "fleet-api-test-secret" };
        options.Seed.Mgmt = new MgmtSeedOptions { Enabled = true, ClientSecret = "mgmt-api-test-secret" };
        options.Seed.Demo = new DemoSeedOptions
        {
            Enabled = true,
            WebSecret = "demo-web-test-secret",
            ServiceSecret = "demo-service-test-secret",
        };
        options.TenantRouting.Bindings =
        [
            new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAuth, Zone = "s001", State = TenantRouteState.Ready },
            new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAssistant, Zone = "s001", State = TenantRouteState.Ready },
        ];

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var seeded = new HashSet<string>(StringComparer.Ordinal);
        await foreach (var application in applications.ListAsync())
        {
            seeded.Add((await applications.GetClientIdAsync(application))!);
        }

        // 播种 ⊆ 保留名单（防漂移方向：新播种项必须登记）。
        Assert.All(seeded, clientId => Assert.Contains(clientId, FirstPartyClients.All));
        // 保留名单中除宿主命令注册的 website-admin 外全部实际播种（防名单空挂/播种静默跳过）。
        Assert.All(FirstPartyClients.All.Where(id => id != FirstPartyClients.WebsiteAdmin),
            clientId => Assert.Contains(clientId, seeded));
    }

    [Fact]
    public async Task PandaAssistantBinding_SeedsAsstClientsWithZoneCallbacksAndIntrospection()
    {
        // PANDA-INFRA-R1（panda-asst ADR 0095）：asst 客户端族的回调按 PandaAssistant 绑定展开，
        // asst-server 只授内省端点；asst-mobile 公共客户端无密钥。
        var options = ValidOptions();
        options.Seed.AsstWeb = new AsstWebSeedOptions
        {
            Enabled = true,
            ClientSecret = "asst-web-secret-0123456789abcdef",
            RedirectUris = ["https://asst.example.local/app/callback/pandaauth"],
            PostLogoutRedirectUris = ["https://asst.example.local/app/"],
        };
        options.Seed.AsstAdmin = new AsstAdminSeedOptions
        {
            Enabled = true,
            ClientSecret = "asst-admin-secret-0123456789abcd",
            RedirectUris = ["https://asst.example.local/admin/callback/pandaauth"],
            PostLogoutRedirectUris = ["https://asst.example.local/admin/"],
        };
        options.Seed.AsstMobile = new AsstMobileSeedOptions
        {
            Enabled = true,
            RedirectUris = ["https://t0042-asst.s001.pandalabs.cn/app/callback/mobile"],
            PostLogoutRedirectUris = ["https://t0042-asst.s001.pandalabs.cn/app/"],
        };
        options.Seed.AsstServer = new AsstServerSeedOptions
        {
            Enabled = true,
            ClientSecret = "asst-server-secret-0123456789abcdef",
        };
        options.TenantRouting.Bindings =
        [
            new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAuth, Zone = "s001", State = TenantRouteState.Ready },
            new TenantRouteBindingOptions { TenantId = "t0042", Product = TenantProduct.PandaAssistant, Zone = "s001", State = TenantRouteState.Ready },
        ];

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var asstWeb = await applications.FindByClientIdAsync("asst-web");
        var asstAdmin = await applications.FindByClientIdAsync("asst-admin");
        var asstMobile = await applications.FindByClientIdAsync("asst-mobile");
        var asstServer = await applications.FindByClientIdAsync("asst-server");
        Assert.NotNull(asstWeb);
        Assert.NotNull(asstAdmin);
        Assert.NotNull(asstMobile);
        Assert.NotNull(asstServer);

        // 租户展开：asst 主机（PandaAssistant 绑定）进入 asst-web/asst-admin 白名单，
        // 且不污染 me-web/admin-web 的 auth 主机白名单口径。
        Assert.Contains("https://t0042-asst.s001.pandalabs.cn/app/callback/login/pandaauth",
            await applications.GetRedirectUrisAsync(asstWeb));
        // post-logout 为专用路径（根路径会被 OpenIddict 客户端拦截成无 state 回调 400，me-web 教训）。
        Assert.Contains("https://t0042-asst.s001.pandalabs.cn/app/callback/logout/pandaauth",
            await applications.GetPostLogoutRedirectUrisAsync(asstWeb));
        Assert.Contains("https://t0042-asst.s001.pandalabs.cn/admin/callback/login/pandaauth",
            await applications.GetRedirectUrisAsync(asstAdmin));
        Assert.Contains("https://t0042-asst.s001.pandalabs.cn/admin/callback/logout/pandaauth",
            await applications.GetPostLogoutRedirectUrisAsync(asstAdmin));

        // asst-mobile：App Links 回调按配置入库（公共客户端无密钥可验）。
        Assert.Contains("https://t0042-asst.s001.pandalabs.cn/app/callback/mobile",
            await applications.GetRedirectUrisAsync(asstMobile));

        // asst-server：密钥可验 + 内省权限（无回调面）。
        Assert.True(await applications.ValidateClientSecretAsync(asstServer, "asst-server-secret-0123456789abcdef"));
        Assert.Empty(await applications.GetRedirectUrisAsync(asstServer));
    }

    [Fact]
    public async Task AdminWebMissingWithoutRedirectUris_Throws()
    {
        var options = ValidOptions();
        options.Seed.AdminWeb.RedirectUris = [];

        using var provider = BuildProvider(options);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DbSeeder.SeedAsync(provider));

        Assert.Contains("Auth:Seed:AdminWeb:RedirectUris", exception.Message);
    }

    [Fact]
    public async Task AdminWebExists_ClientSecretDriftIsReconciledAndWhitelistKept()
    {
        const string configuredSecret = "admin-web-configured-secret";
        var options = ValidOptions();
        options.Seed.AdminWeb.ClientSecret = configuredSecret;
        options.Seed.AdminWeb.RedirectUris = [];
        options.Seed.AdminWeb.PostLogoutRedirectUris = [];

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "admin-web",
            "PandaAuth 管理后台",
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "admin-web-original-secret");

        await DbSeeder.SeedAsync(provider);

        var adminWeb = await applications.FindByClientIdAsync("admin-web");
        Assert.NotNull(adminWeb);
        Assert.True(await applications.ValidateClientSecretAsync(adminWeb, configuredSecret));
        Assert.False(await applications.ValidateClientSecretAsync(adminWeb, "admin-web-original-secret"));

        // 未配白名单 → 存量白名单原样保留。
        var redirectUris = await applications.GetRedirectUrisAsync(adminWeb);
        Assert.Equal(new[] { LegacyRedirectUri }, redirectUris.OrderBy(x => x));
    }

    [Fact]
    public async Task AdminWebDisabled_SkipsSeedAndUpsert()
    {
        var options = ValidOptions();
        options.Seed.AdminWeb.Enabled = false;
        options.Seed.AdminWeb.RedirectUris = [];
        options.Seed.AdminWeb.PostLogoutRedirectUris = [];
        options.Seed.AdminWeb.ClientSecret = "";

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("admin-web"));
    }

    // oasis-web 与 me-web/admin-web 共用 SeedFirstPartyWebApplicationAsync（经 permissions 参数注入裁剪权限集）；
    // 方法级 upsert 行为（白名单整体替换、密钥幂等对账、明文不得入库）已由 me-web 套件覆盖，
    // 这里验证 oasis-web 调用点的接线：默认关闭、独立开关、白名单取值、裁剪后的权限集与失败关闭。
    // Revocation 端点权限刻意保留（Oasis 登出走 RP-initiated signout + revoke，me-web 模式）；
    // 裁掉的是 roles scope 与 Introspection 端点（Oasis 不请求 roles、不消费内省）。

    [Fact]
    public async Task OasisWebDisabledByDefault_DoesNotCreateClient()
    {
        // OasisWebSeedOptions 默认 Enabled=false（与 Fleet/Mgmt 同策略）：社区自托管默认不播种，
        // 也不会因缺 ClientSecret 让 migrate 失败。
        var options = ValidOptions();

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("oasis-web"));

        // 同轮里 me-web / admin-web 照常播种，证明 Seeder 确实执行过。
        Assert.NotNull(await applications.FindByClientIdAsync("me-web"));
        Assert.NotNull(await applications.FindByClientIdAsync("admin-web"));
    }

    [Fact]
    public async Task OasisWebEnabled_CreatesConfidentialClientWithTrimmedPermissions()
    {
        var options = ValidOptions();
        options.Seed.OasisWeb = new OasisWebSeedOptions
        {
            Enabled = true,
            ClientSecret = OasisWebClientSecret,
            RedirectUris = [OasisWebRedirectUri, "http://localhost:5000/signin-oidc"],
            PostLogoutRedirectUris = [OasisWebPostLogoutUri],
        };

        using var provider = BuildProvider(options);
        await DbSeeder.SeedAsync(provider);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var oasisWeb = await applications.FindByClientIdAsync("oasis-web");
        Assert.NotNull(oasisWeb);
        Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(oasisWeb));
        Assert.True(await applications.ValidateClientSecretAsync(oasisWeb, OasisWebClientSecret));

        var redirectUris = await applications.GetRedirectUrisAsync(oasisWeb);
        Assert.Equal(
            new[] { OasisWebRedirectUri, "http://localhost:5000/signin-oidc" }.OrderBy(x => x),
            redirectUris.OrderBy(x => x));

        var postLogoutUris = await applications.GetPostLogoutRedirectUrisAsync(oasisWeb);
        Assert.Equal(new[] { OasisWebPostLogoutUri }, postLogoutUris.OrderBy(x => x));

        // 与 me-web 权限集相同的基础项：授权码 + PKCE + 刷新令牌，openid 侧 email/profile/offline_access。
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.Endpoints.Authorization));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.Endpoints.Token));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.Endpoints.EndSession));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.Endpoints.Revocation));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.GrantTypes.AuthorizationCode));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.GrantTypes.RefreshToken));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.ResponseTypes.Code));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.Scopes.Email));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.Scopes.Profile));
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Permissions.Prefixes.Scope + Scopes.OfflineAccess));
        // PKCE 条目与 me-web 同形态落在 Permissions 集（HasRequirementAsync 查的是 Requirements 集，恒为 false）；
        // 实际强制力来自服务端全局 RequireProofKeyForCodeExchange()，此处只是与 me-web seed 块逐字对齐。
        Assert.True(await applications.HasPermissionAsync(oasisWeb, Requirements.Features.ProofKeyForCodeExchange));

        // 裁剪项：不授 roles scope（Oasis 授权完全在本地），不授 Introspection 端点（无内省消费方）。
        Assert.False(await applications.HasPermissionAsync(oasisWeb, Permissions.Scopes.Roles));
        Assert.False(await applications.HasPermissionAsync(oasisWeb, Permissions.Endpoints.Introspection));

        // me-web 权限集不受 oasis-web 接线影响。
        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);
        Assert.True(await applications.HasPermissionAsync(meWeb, Permissions.Scopes.Roles));
        Assert.True(await applications.HasPermissionAsync(meWeb, Permissions.Endpoints.Revocation));
    }

    [Fact]
    public async Task OasisWebEnabledWithoutSecret_FailsClosed()
    {
        var options = ValidOptions();
        options.Seed.OasisWeb = new OasisWebSeedOptions
        {
            Enabled = true,
            ClientSecret = "",
            RedirectUris = [OasisWebRedirectUri],
            PostLogoutRedirectUris = [OasisWebPostLogoutUri],
        };

        using var provider = BuildProvider(options);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DbSeeder.SeedAsync(provider));

        Assert.Contains("Auth:Seed:OasisWeb:ClientSecret", exception.Message);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("oasis-web"));
    }

    [Fact]
    public async Task OasisWebExists_ClientSecretDriftIsReconciledAndWhitelistReplaced()
    {
        const string configuredSecret = "oasis-web-configured-secret";
        var options = ValidOptions();
        options.Seed.OasisWeb = new OasisWebSeedOptions
        {
            Enabled = true,
            ClientSecret = configuredSecret,
            RedirectUris = [OasisWebRedirectUri],
            PostLogoutRedirectUris = [OasisWebPostLogoutUri],
        };

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateFirstPartyWebAsync(applications,
            "oasis-web",
            "Oasis 工作台",
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "oasis-web-original-secret");

        await DbSeeder.SeedAsync(provider);

        var oasisWeb = await applications.FindByClientIdAsync("oasis-web");
        Assert.NotNull(oasisWeb);
        Assert.True(await applications.ValidateClientSecretAsync(oasisWeb, configuredSecret));
        Assert.False(await applications.ValidateClientSecretAsync(oasisWeb, "oasis-web-original-secret"));

        var redirectUris = await applications.GetRedirectUrisAsync(oasisWeb);
        Assert.Equal(new[] { OasisWebRedirectUri }, redirectUris.OrderBy(x => x));
        var postLogoutUris = await applications.GetPostLogoutRedirectUrisAsync(oasisWeb);
        Assert.Equal(new[] { OasisWebPostLogoutUri }, postLogoutUris.OrderBy(x => x));
    }

    /// <summary>构造播种总开关开启、Me 配置齐全、Demo 默认关闭的合法选项。</summary>
    private static AuthOptions ValidOptions() => new()
    {
        Seed = new SeedOptions
        {
            Enabled = true,
            Admin = new AdminSeedOptions { Email = "admin@example.com", Password = "" },
            Me = new MeSeedOptions
            {
                Enabled = true,
                ClientSecret = MeClientSecret,
                RedirectUris = [MeRedirectUri],
                PostLogoutRedirectUris = [MePostLogoutUri],
            },
            AdminWeb = new AdminWebSeedOptions
            {
                Enabled = true,
                ClientSecret = AdminWebClientSecret,
                RedirectUris = [AdminWebRedirectUri],
                PostLogoutRedirectUris = [AdminWebPostLogoutUri],
            },
            Demo = new DemoSeedOptions(),
        },
    };

    /// <summary>以真实 OpenIddict Core 管理器 + EF InMemory 构建 Seeder 所需的服务容器。</summary>
    private static ServiceProvider BuildProvider(AuthOptions options)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(options));
        services.AddDbContext<PandaAuthDbContext>(builder => builder
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .UseOpenIddict());
        services.AddUserStore();
        services.AddOpenIddict()
            .AddCore(builder => builder.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        return services.BuildServiceProvider();
    }

    /// <summary>从 EF 直读指定客户端的 ClientSecret 列（哈希原文），用于断言哈希是否被无意义重写。</summary>
    private static async Task<string?> ReadStoredClientSecretAsync(ServiceProvider provider, string clientId)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        return await db.Set<OpenIddictEntityFrameworkCoreApplication>()
            .AsNoTracking()
            .Where(x => x.ClientId == clientId)
            .Select(x => x.ClientSecret)
            .SingleAsync();
    }

    /// <summary>模拟存量第一方 Web 客户端（me-web / admin-web）：旧回调 + 旧密钥。</summary>
    private static async Task CreateFirstPartyWebAsync(
        IOpenIddictApplicationManager applications,
        string clientId,
        string displayName,
        string[] redirectUris,
        string[] postLogoutUris,
        string clientSecret)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = ClientTypes.Confidential,
            ClientSecret = clientSecret,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = displayName,
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,
                Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                Requirements.Features.ProofKeyForCodeExchange,
            },
        };

        foreach (var uri in redirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        foreach (var uri in postLogoutUris)
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        await applications.CreateAsync(descriptor);
    }
}
