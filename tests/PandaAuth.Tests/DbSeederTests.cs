using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>Seeder 集成测试：EF InMemory + 真实 OpenIddict Core 管理器，验证播种开关与 me-web upsert 行为。</summary>
public class DbSeederTests
{
    private const string MeRedirectUri = "https://auth.pandalabs.cc/me/callback/login/pandaauth";

    private const string MePostLogoutUri = "https://auth.pandalabs.cc/me/";

    private const string MeClientSecret = "me-web-test-secret";

    // 密钥对账用例用的存量旧回调：刻意不用已退役域名，避免与域名退役门禁的
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

        // 总开关开启时仅播种第一方客户端，证明 Seeder 确实执行过。
        Assert.NotNull(await applications.FindByClientIdAsync("me-web"));
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
        await CreateMeWebAsync(applications,
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
        await CreateMeWebAsync(applications,
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
        Assert.NotEqual(configuredSecret, await ReadStoredClientSecretAsync(provider));

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
        await CreateMeWebAsync(applications,
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "me-web-original-secret");

        await DbSeeder.SeedAsync(provider);
        var afterFirstRun = await ReadStoredClientSecretAsync(provider);

        await DbSeeder.SeedAsync(provider);
        var afterSecondRun = await ReadStoredClientSecretAsync(provider);

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
        await CreateMeWebAsync(applications,
            redirectUris: [LegacyRedirectUri],
            postLogoutUris: [LegacyPostLogoutUri],
            clientSecret: "me-web-original-secret");
        var hashBefore = await ReadStoredClientSecretAsync(provider);

        await DbSeeder.SeedAsync(provider);

        var meWeb = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(meWeb);
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, "me-web-original-secret"));
        Assert.Equal(hashBefore, await ReadStoredClientSecretAsync(provider));

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
        await CreateMeWebAsync(applications,
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
        Assert.True(await applications.ValidateClientSecretAsync(meWeb, "me-web-dev-secret"));

        var userManager = provider.GetRequiredService<UserManager<PandaAuthUser>>();
        Assert.NotNull(await userManager.FindByNameAsync("admin@pandalabs.cc"));
    }

    [Fact]
    public async Task MeDisabled_SkipsMeWebSeedAndUpsert()
    {
        // 预置 .cn 回调的存量 me-web；Me.Enabled=false 时既不播种也不订正。
        var options = ValidOptions();
        options.Seed.Me.Enabled = false;

        using var provider = BuildProvider(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await CreateMeWebAsync(applications,
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

    /// <summary>构造播种总开关开启、Me 配置齐全、Demo 默认关闭的合法选项。</summary>
    private static AuthOptions ValidOptions() => new()
    {
        Seed = new SeedOptions
        {
            Enabled = true,
            Admin = new AdminSeedOptions { Email = "admin@pandalabs.cc", Password = "" },
            Me = new MeSeedOptions
            {
                Enabled = true,
                ClientSecret = MeClientSecret,
                RedirectUris = [MeRedirectUri],
                PostLogoutRedirectUris = [MePostLogoutUri],
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
        services.AddIdentityCore<PandaAuthUser>()
            .AddRoles<PandaAuthRole>()
            .AddEntityFrameworkStores<PandaAuthDbContext>();
        services.AddOpenIddict()
            .AddCore(builder => builder.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        return services.BuildServiceProvider();
    }

    /// <summary>从 EF 直读 me-web 的 ClientSecret 列（哈希原文），用于断言哈希是否被无意义重写。</summary>
    private static async Task<string?> ReadStoredClientSecretAsync(ServiceProvider provider)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        return await db.Set<OpenIddictEntityFrameworkCoreApplication>()
            .AsNoTracking()
            .Where(x => x.ClientId == "me-web")
            .Select(x => x.ClientSecret)
            .SingleAsync();
    }

    /// <summary>模拟事故前的存量 me-web：固定 .cn 回调 + 旧密钥。</summary>
    private static async Task CreateMeWebAsync(
        IOpenIddictApplicationManager applications,
        string[] redirectUris,
        string[] postLogoutUris,
        string clientSecret)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "me-web",
            ClientType = ClientTypes.Confidential,
            ClientSecret = clientSecret,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "PandaAuth 账户中心",
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
