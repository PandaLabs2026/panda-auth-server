using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// 热路径性能与 Seeder 可观测性回归：cookie 校验 stamp 短缓存（命中免查库、stamp 轮换立即生效、
/// 冻结类状态变化最迟 TTL 生效）；DbSeeder 密钥对账改写必须留下 admin_audit 痕迹（改写发生与
/// 未发生两条路径都钉住）。
/// </summary>
public class PerfAndSeederTests
{
    private const string CorrectPassword = "Strong!Pass123";

    [Fact]
    public async Task StampCache_SecondValidationWithinTtlSkipsDatabase()
    {
        using var provider = TestUserStoreHost.Create();
        var (users, user) = await CreateUserAsync(provider);
        var spy = new SpyUserService(
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<IPasswordHasher>(),
            provider.GetRequiredService<TimeProvider>());
        // 用 provider 的 IMemoryCache 单例：UserService 轮换 stamp 时作废的就是这个实例，
        // 与生产路径（校验与作废共享同一单例）一致。
        var cache = provider.GetRequiredService<IMemoryCache>();
        var context = ValidationContext(provider, user);

        await LoginSessionService.ValidateCookieAsync(context, spy, cache);
        var queriesAfterFirst = spy.FindByIdCalls;

        // 同 stamp 第二次校验：命中缓存，不再查库（可数桩直接观测）。
        await LoginSessionService.ValidateCookieAsync(context, spy, cache);
        Assert.Equal(queriesAfterFirst, spy.FindByIdCalls);
        Assert.NotNull(context.Principal);

        // stamp 轮换（改密）：UserService 同步作废旧 stamp 的缓存键，旧 cookie 立即失效
        // （构造旧 stamp 主体验证——user 实例的 stamp 已就地更新，不能直接复用）。
        var oldStamp = user.SecurityStamp;
        await users.ReplacePasswordAsync(user, "Rotated!Pass123");
        var rotated = ValidationContext(provider, user, oldStamp);
        await LoginSessionService.ValidateCookieAsync(rotated, spy, cache);
        Assert.Equal(queriesAfterFirst + 1, spy.FindByIdCalls);
        Assert.Null(rotated.Principal);
    }

    [Fact]
    public async Task StampCache_FrozenUserStillValidUntilTtl_TradeoffWindow()
    {
        // 取舍钉住：冻结不轮换 stamp，缓存命中期间（60 秒内）旧会话仍通过校验——
        // 这是「每请求一查库」与「状态即时生效」之间的显式让步（见 LoginSessionService 注释）。
        using var provider = TestUserStoreHost.Create();
        var (users, user) = await CreateUserAsync(provider);
        var spy = new SpyUserService(
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<IPasswordHasher>(),
            provider.GetRequiredService<TimeProvider>());
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var context = ValidationContext(provider, user);
        await LoginSessionService.ValidateCookieAsync(context, spy, cache);

        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.Users.Single(u => u.Id == user.Id).Status = UserStatus.Frozen;
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        var withinWindow = ValidationContext(provider, user);
        await LoginSessionService.ValidateCookieAsync(withinWindow, spy, cache);
        Assert.NotNull(withinWindow.Principal);
        Assert.Equal(1, spy.FindByIdCalls);

        // 校验失败结果绝不缓存：另一用户维度的失败（此处直接用新缓存）必须查库并拒绝。
        using var freshCache = new MemoryCache(new MemoryCacheOptions());
        var frozenContext = ValidationContext(provider, user);
        await LoginSessionService.ValidateCookieAsync(frozenContext, spy, freshCache);
        Assert.Null(frozenContext.Principal);
    }

    [Fact]
    public async Task ReadPath_NoTracking_DoesNotBreakTrackedMutationFlows()
    {
        // AsNoTracking 的安全锚点：登录失败计数（VerifyLoginAsync 在游离实体上累积 AccessFailedCount
        // 并经 UpdateAsync 落库）与后续锁定读取全链路仍工作。
        var options = new PandaAuth.Server.Configuration.AuthOptions();
        options.RateLimit.IpPerMinute = 30;
        options.RateLimit.AccountPerMinute = 30;
        using var provider = TestUserStoreHost.Create(options);
        var (users, user) = await CreateUserAsync(provider);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var outcome = await new LoginSessionService(
                provider.GetRequiredService<UserService>(),
                provider.GetRequiredService<TimeProvider>())
                .CheckPasswordSignInAsync((await users.FindByNameAsync(user.UserName!))!, "Wrong!Pass123", true);
            Assert.False(outcome.Succeeded);
        }

        var locked = await users.FindByNameAsync(user.UserName!);
        Assert.NotNull(locked!.LockoutEnd);
        Assert.True(locked.LockoutEnd > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task DbSeeder_SecretRewriteWritesAdminAudit()
    {
        var options = ValidSeederOptions();
        using var provider = SeederHost(options);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();

        // 预置 me-web：密钥与种子配置不一致（模拟线上轮换过的值）。
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "me-web",
            ClientType = ClientTypes.Confidential,
            ClientSecret = "rotated-online-secret",
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "stale",
            Permissions = { Permissions.Endpoints.Authorization },
        });

        await DbSeeder.SeedAsync(provider);

        // 改写确实发生：种子密钥可验、旧密钥失效。
        var seeded = await applications.FindByClientIdAsync("me-web");
        Assert.NotNull(seeded);
        Assert.True(await applications.ValidateClientSecretAsync(seeded!, "me-web-test-secret"));
        Assert.False(await applications.ValidateClientSecretAsync(seeded, "rotated-online-secret"));

        // 且留下 admin_audit 痕迹：只含 clientId 与配置键，绝不含密钥值。
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var entry = await db.AdminAuditLogs.SingleAsync(log => log.Action == "seed.client_secret_rewritten");
        Assert.Equal("client", entry.TargetType);
        Assert.Equal("me-web", entry.TargetId);
        Assert.Contains("Auth:Seed:Me", entry.Detail);
        Assert.DoesNotContain("me-web-test-secret", entry.Detail);
    }

    [Fact]
    public async Task DbSeeder_MatchingSecretWritesNoRewriteAudit()
    {
        // 幂等路径钉住：密钥一致时不改写、不留痕——审计只属于真实发生的高危动作。
        var options = ValidSeederOptions();
        using var provider = SeederHost(options);
        await DbSeeder.SeedAsync(provider);

        var db = provider.GetRequiredService<PandaAuthDbContext>();
        Assert.Empty(db.AdminAuditLogs.Where(log => log.Action == "seed.client_secret_rewritten").ToList());
    }

    // ---- 基建 ----

    private static async Task<(UserService Users, PandaUser User)> CreateUserAsync(ServiceProvider provider)
    {
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = $"perf-{Guid.NewGuid():N}" };
        await users.CreateAsync(user, CorrectPassword);
        return (users, user);
    }

    private static CookieValidatePrincipalContext ValidationContext(
        ServiceProvider provider, PandaUser user, string? stampOverride = null)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(LoginSessionService.StampClaim, stampOverride ?? user.SecurityStamp ?? ""),
        ], LoginSessionService.Scheme));
        var ticket = new AuthenticationTicket(principal, LoginSessionService.Scheme);
        return new CookieValidatePrincipalContext(
            new DefaultHttpContext { RequestServices = provider },
            new AuthenticationScheme(LoginSessionService.Scheme, null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(),
            ticket);
    }

    private static PandaAuth.Server.Configuration.AuthOptions ValidSeederOptions() => new()
    {
        Seed = new PandaAuth.Server.Configuration.SeedOptions
        {
            Enabled = true,
            Admin = new PandaAuth.Server.Configuration.AdminSeedOptions { Email = "admin@example.com", Password = "" },
            Me = new PandaAuth.Server.Configuration.MeSeedOptions
            {
                Enabled = true,
                ClientSecret = "me-web-test-secret",
                RedirectUris = ["https://auth.pandalabs.cn/me/callback/login/pandaauth"],
                PostLogoutRedirectUris = ["https://auth.pandalabs.cn/me/"],
            },
            AdminWeb = new PandaAuth.Server.Configuration.AdminWebSeedOptions { Enabled = false },
        },
    };

    /// <summary>与 DbSeederTests.BuildProvider 同构：真实 OpenIddict Core 管理器 + EF InMemory。</summary>
    private static ServiceProvider SeederHost(PandaAuth.Server.Configuration.AuthOptions options)
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

    /// <summary>可数桩：包一层真实 UserService，只对 FindByIdAsync 计数（缓存行为需观测查库次数）。</summary>
    /// <summary>可数桩：与被测 UserService 共用同一批作用域协作者（同 DbContext），查库计数才真实。</summary>
    private sealed class SpyUserService(
        PandaAuthDbContext db, IPasswordHasher hasher, TimeProvider clock) : UserService(db, hasher, clock)
    {
        public int FindByIdCalls { get; private set; }

        public override Task<PandaUser?> FindByIdAsync(string id)
        {
            FindByIdCalls++;
            return base.FindByIdAsync(id);
        }
    }
}
