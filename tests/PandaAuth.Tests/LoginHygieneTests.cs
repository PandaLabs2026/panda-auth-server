using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 登录卫生回归：用户可见失败文案一律「用户名或密码错误。」——区分冻结/锁定文案等于免费向
/// 撞库者确认账号存在；真实原因只落 login_logs（account_frozen/locked_out，运维可辨）。
/// 兼管 TwoFactorEnabled 判定口径：VerifyLoginAsync 只看标志，控制器以活跃因子复核对齐
/// MfaService.MfaStatus 的「标志开启且无活跃因子才需重配置」。
/// </summary>
public class LoginHygieneTests
{
    private const string CorrectPassword = "Strong!Pass123";
    private static readonly byte[] TotpKey = Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    [Fact]
    public async Task FrozenAccount_ShowsGenericCopy_ButAuditsRealReason()
    {
        var hasher = new RecordingHasher();
        using var provider = TestUserStoreHost.Create(passwordHasher: hasher);
        var users = provider.GetRequiredService<UserService>();
        var frozen = new PandaUser { UserName = "frozen-hygiene", Status = UserStatus.Frozen };
        Assert.True((await users.CreateAsync(frozen, CorrectPassword)).Succeeded);

        var view = Assert.IsType<ViewResult>(await Controller(provider, hasher: hasher).Login(
            new LoginViewModel { UserName = "frozen-hygiene", Password = "Wrong!Pass123" }, CancellationToken.None));

        Assert.Equal("用户名或密码错误。", ViewError(view));
        var entry = await provider.GetRequiredService<PandaAuthDbContext>().LoginLogs.SingleAsync();
        Assert.False(entry.Succeeded);
        Assert.Equal("account_frozen", entry.FailureReason);
        // 耗时拉平语义不因文案统一而回退：冻结路径仍对 dummy 哈希支付一次校验。
        Assert.Equal(1, hasher.VerifyCalls);
    }

    [Fact]
    public async Task LockedOutAccount_ShowsGenericCopy_ButAuditsRealReason()
    {
        var options = new AuthOptions();
        // 抬高限流阈值：聚焦 5 次失败触发的账号锁定，别让固定窗口限流先挡住第 5/6 次尝试。
        options.RateLimit.IpPerMinute = 30;
        options.RateLimit.AccountPerMinute = 30;
        using var provider = TestUserStoreHost.Create(options);
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "locked-hygiene" };
        await users.CreateAsync(user, CorrectPassword);

        for (var attempt = 1; attempt <= 6; attempt++)
        {
            // 第 5 次失败触发 5 分钟锁定；第 6 次即使口令正确也被拒——文案两处都必须统一。
            var view = Assert.IsType<ViewResult>(await Controller(provider).Login(
                new LoginViewModel
                {
                    UserName = "locked-hygiene",
                    Password = attempt < 6 ? "Wrong!Pass123" : CorrectPassword,
                },
                CancellationToken.None));
            Assert.Equal("用户名或密码错误。", ViewError(view));
        }

        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var logs = await db.LoginLogs.OrderBy(log => log.Id).ToListAsync();
        Assert.Equal(6, logs.Count);
        Assert.All(logs, log => Assert.False(log.Succeeded));
        Assert.All(logs.Take(4), log => Assert.Equal("wrong_password", log.FailureReason));
        Assert.Equal("locked_out", logs[4].FailureReason);
        Assert.Equal("locked_out", logs[5].FailureReason);
    }

    [Fact]
    public async Task StaleTwoFactorFlagWithActiveFactor_SelfHealsAndSignsInDirectly()
    {
        // LoginMfa 关闭：自愈后走直登（落 /me/），不再被遗留标志拖进重配置流。
        var (provider, user) = await HostWithFlaggedUserAndTotpFactorAsync(loginMfaEnabled: false);

        var controller = Controller(provider, withMfa: true);
        var action = await controller.Login(
            new LoginViewModel { UserName = user.UserName!, Password = CorrectPassword }, CancellationToken.None);

        var redirect = Assert.IsType<LocalRedirectResult>(action);
        Assert.Equal("/me/", redirect.Url);
        Assert.NotNull(Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
        var healed = await provider.GetRequiredService<UserService>().FindByNameAsync(user.UserName!);
        Assert.False(healed!.TwoFactorEnabled, "标志应被自愈清除");
        var log = await provider.GetRequiredService<PandaAuthDbContext>().LoginLogs.SingleAsync();
        Assert.True(log.Succeeded);
        Assert.Null(log.FailureReason);
    }

    [Fact]
    public async Task StaleTwoFactorFlagWithActiveFactor_SelfHealsAndEntersLoginMfaChallenge()
    {
        // LoginMfa 开启：自愈后照常进入挑战（pending 挑战 cookie，无已认证身份），而不是重配置。
        var (provider, user) = await HostWithFlaggedUserAndTotpFactorAsync(loginMfaEnabled: true);

        var controller = Controller(provider, withMfa: true);
        var action = await controller.Login(
            new LoginViewModel { UserName = user.UserName!, Password = CorrectPassword }, CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(action);
        Assert.StartsWith("/account/mfa/challenge?returnUrl=", redirect.Url, StringComparison.Ordinal);
        Assert.Null(Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
        Assert.NotNull(Cookie(controller.HttpContext, LoginMfaChallengeService.CookieName));
        Assert.False(
            (await provider.GetRequiredService<UserService>().FindByNameAsync(user.UserName!))!.TwoFactorEnabled);
    }

    [Fact]
    public async Task TwoFactorFlagWithoutActiveFactor_StillRoutesToReconfiguration()
    {
        // 口径对齐的另一半：无活跃因子时维持重配置路径（回归锚点，防止复核逻辑把真重配置也放行）。
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "reconfig-hygiene", TwoFactorEnabled = true };
        Assert.True((await users.CreateAsync(user, CorrectPassword)).Succeeded);

        var controller = Controller(provider, withMfa: true);
        var action = await controller.Login(
            new LoginViewModel { UserName = "reconfig-hygiene", Password = CorrectPassword }, CancellationToken.None);

        var redirect = Assert.IsType<LocalRedirectResult>(action);
        Assert.Equal("/account/mfa/user/reconfigure", redirect.Url);
        Assert.Null(Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
        Assert.NotNull(Cookie(controller.HttpContext, LoginSessionService.ReconfigurationScheme));
    }

    // ---- 基建（与 LoginMfaChallengeTests 同构：真实服务 + InMemory，逐请求新建控制器） ----

    private static async Task<(ServiceProvider Provider, PandaUser User)> HostWithFlaggedUserAndTotpFactorAsync(
        bool loginMfaEnabled)
    {
        var provider = TestUserStoreHost.Create(new AuthOptions
        {
            LoginMfa = new LoginMfaOptions { Enabled = loginMfaEnabled },
        });
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = $"stale-2fa-{Guid.NewGuid():N}", TwoFactorEnabled = true };
        await users.CreateAsync(user, CorrectPassword);
        await SeedTotpFactorAsync(provider, user.Id);
        return (provider, user);
    }

    private static async Task SeedTotpFactorAsync(ServiceProvider provider, string userId)
    {
        var secret = RandomNumberGenerator.GetBytes(20);
        var factorId = Guid.NewGuid();
        var protectedSecret = new TotpSecretProtector(TotpKey, "v1").Protect(userId, factorId, secret);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor
        {
            Id = factorId,
            UserId = userId,
            ConfirmedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            KeyVersion = protectedSecret.KeyVersion,
            Nonce = protectedSecret.Nonce,
            Ciphertext = protectedSecret.Ciphertext,
            Tag = protectedSecret.Tag,
        });
        await db.SaveChangesAsync();
    }

    private static AccountController Controller(ServiceProvider provider, bool withMfa = false, IPasswordHasher? hasher = null)
        => TestUserStoreHost.CreateAccountController(
            provider,
            hasher ?? provider.GetRequiredService<IPasswordHasher>(),
            withMfa ? MfaService(provider) : null,
            withMfa ? provider.GetRequiredService<LoginMfaChallengeService>() : null,
            withMfa ? provider.GetRequiredService<SecurityEventWriter>() : null);

    private static MfaService MfaService(ServiceProvider provider) => new(
        provider.GetRequiredService<PandaAuthDbContext>(),
        provider.GetRequiredService<UserService>(),
        new TotpFactorService(
            provider.GetRequiredService<PandaAuthDbContext>(),
            new TotpSecretProtector(TotpKey, "v1"),
            TimeProvider.System),
        provider.GetRequiredService<LoginSessionService>(),
        TimeProvider.System);

    private static string ViewError(ViewResult view)
        => view.ViewData.ModelState[string.Empty]!.Errors.Single().ErrorMessage;

    private static string? Cookie(Microsoft.AspNetCore.Http.HttpContext context, string name)
    {
        var pair = context.Response.Headers.SetCookie
            .Select(value => value!.Split(';')[0])
            .FirstOrDefault(value => value.StartsWith(name + "=", StringComparison.Ordinal));
        return pair is null ? null : pair[(name.Length + 1)..];
    }

    /// <summary>记录校验次数的 hasher 替身；转发真实 Argon2，保证耗时拉平断言测的是真校验。</summary>
    private sealed class RecordingHasher : IPasswordHasher
    {
        private readonly Argon2idPasswordHasher _inner = new();
        public int VerifyCalls { get; private set; }
        public string? LastHashedPassword { get; private set; }

        public string Hash(string password) => _inner.Hash(password);

        public PasswordVerificationOutcome Verify(string? hashedPassword, string providedPassword)
        {
            VerifyCalls++;
            LastHashedPassword = hashedPassword;
            return _inner.Verify(hashedPassword, providedPassword);
        }
    }
}
