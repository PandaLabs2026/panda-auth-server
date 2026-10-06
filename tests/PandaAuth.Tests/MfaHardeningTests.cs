using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Fido2NetLib;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// MFA 会话卫生与 step-up 加固回归：登出必须清 pending 挑战与重配置 cookie（5 分钟 TTL 内
/// 不允许凭验证码重入）；step-up 断言入口限流（IP+用户双维，与登录挑战同策略）；
/// [FromBody] 端点空体一律 400，不得解引用跌成 500。
/// </summary>
public class MfaHardeningTests
{
    private const string CorrectPassword = "Strong!Pass123";
    private static readonly byte[] TotpKey = Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    [Fact]
    public async Task AccountLogout_ClearsPendingChallengeCookie_AndSubsequentTotpAssertBouncesToLogin()
    {
        using var provider = Host();
        var (_, user, _) = await SeedUserWithTotpFactorAsync(provider);

        // 密码成功进入挑战：上下文拿到 pending 挑战 cookie。
        var login = TestUserStoreHost.CreateAccountController(
            provider, provider.GetRequiredService<IPasswordHasher>(),
            MfaService(provider), provider.GetRequiredService<LoginMfaChallengeService>(),
            provider.GetRequiredService<SecurityEventWriter>());
        await login.Login(
            new LoginViewModel { UserName = user.UserName!, Password = CorrectPassword }, CancellationToken.None);
        var pending = Cookie(login.HttpContext, LoginMfaChallengeService.CookieName);
        Assert.NotNull(pending);

        // 登出：pending 挑战 cookie 必须以过期删除头清除（登出控制器必须持有挑战服务）。
        var logoutContext = new DefaultHttpContext { RequestServices = provider };
        logoutContext.Request.Scheme = "https";
        logoutContext.Request.Headers.Cookie = $"{LoginMfaChallengeService.CookieName}={pending}";
        var logout = TestUserStoreHost.CreateAccountController(
            provider, provider.GetRequiredService<IPasswordHasher>(),
            null, provider.GetRequiredService<LoginMfaChallengeService>(), null);
        logout.ControllerContext.HttpContext = logoutContext;
        Assert.IsType<RedirectResult>(await logout.Logout());
        Assert.Equal(string.Empty, Cookie(logoutContext, LoginMfaChallengeService.CookieName));

        // cookie 已清后，挑战断言只能回登录页（无 pending 主体可续写）。
        var after = new DefaultHttpContext { RequestServices = provider };
        after.Request.Scheme = "https";
        var bounce = Assert.IsType<RedirectResult>(await ChallengeController(provider, after)
            .AssertTotp(new LoginMfaChallengeTotpRequest { Code = "123456" }, CancellationToken.None));
        Assert.Equal("/account/login", bounce.Url);
    }

    [Fact]
    public async Task AccountLogout_ClearsReconfigurationCookie_WhenPresent()
    {
        // 重配置 cookie 与 LoginMfa 开关无关；普通 UserStore 宿主即可复现。
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "reconfig-logout", TwoFactorEnabled = true };
        await users.CreateAsync(user, CorrectPassword);

        using (var scope = provider.CreateScope())
        {
            var issue = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            issue.Request.Scheme = "https";
            issue.Request.Host = new HostString("localhost");
            await scope.ServiceProvider.GetRequiredService<LoginSessionService>()
                .SignInForMfaReconfigurationAsync(issue, user);
            var reconfigCookie = Cookie(issue, LoginSessionService.ReconfigurationScheme);
            Assert.NotNull(reconfigCookie);

            var logoutContext = new DefaultHttpContext { RequestServices = provider };
            logoutContext.Request.Scheme = "https";
            logoutContext.Request.Host = new HostString("localhost");
            logoutContext.Request.Path = "/account/logout";
            logoutContext.Request.Headers.Cookie = $"{LoginSessionService.ReconfigurationScheme}={reconfigCookie}";
            var logout = TestUserStoreHost.CreateAccountController(
                provider, provider.GetRequiredService<IPasswordHasher>(),
                null, provider.GetRequiredService<LoginMfaChallengeService>(), null);
            logout.ControllerContext.HttpContext = logoutContext;
            await logout.Logout();
            Assert.Equal(string.Empty, Cookie(logoutContext, LoginSessionService.ReconfigurationScheme));
        }
    }

    [Fact]
    public async Task ConnectLogout_ClearsReconfigurationCookie_WhenPresent()
    {
        // /connect/logout（end-session）同样清理重配置 cookie；独立宿主避免与本地登录面流程
        // 共享根级 DbContext/认证协作者（同 provider 内多套控制器-上下文流会互相干扰）。
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "reconfig-connect-logout", TwoFactorEnabled = true };
        await users.CreateAsync(user, CorrectPassword);

        using (var scope = provider.CreateScope())
        {
            var issue = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            issue.Request.Scheme = "https";
            issue.Request.Host = new HostString("localhost");
            await scope.ServiceProvider.GetRequiredService<LoginSessionService>()
                .SignInForMfaReconfigurationAsync(issue, user);
            var reconfigCookie = Cookie(issue, LoginSessionService.ReconfigurationScheme);
            Assert.NotNull(reconfigCookie);

            var context = new DefaultHttpContext { RequestServices = provider };
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("localhost");
            context.Request.Headers.Cookie = $"{LoginSessionService.ReconfigurationScheme}={reconfigCookie}";
            var controller = TestUserStoreHost.CreateAuthorizationController(provider);
            controller.ControllerContext.HttpContext = context;
            await controller.Logout();
            Assert.Equal(string.Empty, Cookie(context, LoginSessionService.ReconfigurationScheme));
        }
    }

    [Fact]
    public async Task ConnectLogout_ClearsPendingChallengeCookie()
    {
        using var provider = Host();
        var (_, user, _) = await SeedUserWithTotpFactorAsync(provider);
        var login = TestUserStoreHost.CreateAccountController(
            provider, provider.GetRequiredService<IPasswordHasher>(),
            MfaService(provider), provider.GetRequiredService<LoginMfaChallengeService>(),
            provider.GetRequiredService<SecurityEventWriter>());
        await login.Login(
            new LoginViewModel { UserName = user.UserName!, Password = CorrectPassword }, CancellationToken.None);
        var pending = Cookie(login.HttpContext, LoginMfaChallengeService.CookieName);

        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        context.Request.Headers.Cookie = $"{LoginMfaChallengeService.CookieName}={pending}";
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        controller.ControllerContext.HttpContext = context;

        Assert.IsType<SignOutResult>(await controller.Logout());
        Assert.Equal(string.Empty, Cookie(context, LoginMfaChallengeService.CookieName));
    }

    [Fact]
    public async Task EmptyBody_ReturnsBadRequestInsteadOf500()
    {
        using var provider = Host();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "empty-body" };
        await users.CreateAsync(user, CorrectPassword);
        var controller = UserMfaController(provider, user.Id);

        // 用户面四个空体端点 + 重配置确认：全部 400「请求体缺失。」，不再 NRE→500。
        await AssertEmptyBodyAsync(() => controller.ConfirmUserTotp(null!, CancellationToken.None));
        await AssertEmptyBodyAsync(() => controller.AssertUserTotp(null!, CancellationToken.None));
        await AssertEmptyBodyAsync(() => controller.RevokeUserFactor(null!, CancellationToken.None));
        await AssertEmptyBodyAsync(() => controller.ConsumeUserRecoveryCode(null!, CancellationToken.None));

        var reconfigUser = new PandaUser { UserName = "empty-body-reconfig", TwoFactorEnabled = true };
        await users.CreateAsync(reconfigUser, CorrectPassword);
        using (var scope = provider.CreateScope())
        {
            var issue = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            issue.Request.Scheme = "https";
            await scope.ServiceProvider.GetRequiredService<LoginSessionService>()
                .SignInForMfaReconfigurationAsync(issue, reconfigUser);
            var reconfigCookie = Cookie(issue, LoginSessionService.ReconfigurationScheme);
            var reconfigContext = new DefaultHttpContext { RequestServices = provider };
            reconfigContext.Request.Scheme = "https";
            reconfigContext.Request.Headers.Cookie = $"{LoginSessionService.ReconfigurationScheme}={reconfigCookie}";
            var reconfigController = UserMfaController(provider, reconfigUser.Id);
            reconfigController.ControllerContext.HttpContext = reconfigContext;
            await AssertEmptyBodyAsync(() => reconfigController.ConfirmLegacyTotpReconfiguration(null!, CancellationToken.None));
        }
    }

    [Fact]
    public async Task AssertUserTotp_IsRateLimitedPerUser_AfterWindowBudget()
    {
        var options = new AuthOptions();
        options.LoginMfa.Enabled = true;
        options.RateLimit.MfaChallengeAccountPerMinute = 2;
        using var provider = TestUserStoreHost.Create(options);
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "limited-member" };
        await users.CreateAsync(user, CorrectPassword);

        var controller = UserMfaController(provider, user.Id);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var bad = Assert.IsType<BadRequestObjectResult>(await controller.AssertUserTotp(
                new ConfirmTotpRequest { FactorId = Guid.NewGuid(), Code = "000000" }, CancellationToken.None));
            Assert.Contains("验证码错误", bad.Value!.ToString(), StringComparison.Ordinal);
        }

        // 第 3 次即使验证码正确也被限流拒绝——六位码可暴力尝试，必须先于校验拒绝。
        var limited = Assert.IsType<ObjectResult>(await controller.AssertUserTotp(
            new ConfirmTotpRequest { FactorId = Guid.NewGuid(), Code = "123456" }, CancellationToken.None));
        Assert.Equal(StatusCodes.Status429TooManyRequests, limited.StatusCode);
        Assert.Contains("尝试过于频繁", limited.Value!.ToString(), StringComparison.Ordinal);
    }

    // ---- 基建 ----

    private static ServiceProvider Host()
        => TestUserStoreHost.Create(new AuthOptions { LoginMfa = new LoginMfaOptions { Enabled = true } });

    private static async Task AssertEmptyBodyAsync(Func<Task<IActionResult>> action)
    {
        var bad = Assert.IsType<BadRequestObjectResult>(await action());
        Assert.Equal(StatusCodes.Status400BadRequest, bad.StatusCode);
        Assert.Contains("请求体缺失", bad.Value!.ToString(), StringComparison.Ordinal);
    }

    private static MfaController UserMfaController(ServiceProvider provider, string userId)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, userId)], LoginSessionService.Scheme));
        var totp = new TotpFactorService(db, new TotpSecretProtector(TotpKey, "v1"), TimeProvider.System);
        return new MfaController(
            provider.GetRequiredService<UserService>(),
            new WebAuthnCeremonyService(
                new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                db, new MfaChallengeStore(db, TimeProvider.System)),
            totp,
            provider.GetRequiredService<LoginSessionService>(),
            db,
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            new MfaService(
                db, provider.GetRequiredService<UserService>(), totp,
                provider.GetRequiredService<LoginSessionService>(), TimeProvider.System))
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
    }

    private static MfaService MfaService(ServiceProvider provider) => new(
        provider.GetRequiredService<PandaAuthDbContext>(),
        provider.GetRequiredService<UserService>(),
        new TotpFactorService(
            provider.GetRequiredService<PandaAuthDbContext>(),
            new TotpSecretProtector(TotpKey, "v1"),
            TimeProvider.System),
        provider.GetRequiredService<LoginSessionService>(),
        TimeProvider.System);

    private static LoginMfaChallengeController ChallengeController(ServiceProvider provider, DefaultHttpContext context)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        return new LoginMfaChallengeController(
            provider.GetRequiredService<UserService>(),
            MfaService(provider),
            new WebAuthnCeremonyService(
                new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                db, new MfaChallengeStore(db, TimeProvider.System)),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<LoginMfaChallengeService>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            provider.GetRequiredService<SecurityEventWriter>())
        {
            ControllerContext = new ControllerContext(new ActionContext(
                context,
                new Microsoft.AspNetCore.Routing.RouteData(),
                new Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor())),
        };
    }

    private static async Task<(UserService Users, PandaUser User, byte[] Secret)> SeedUserWithTotpFactorAsync(
        ServiceProvider provider)
    {
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = $"hardening-{Guid.NewGuid():N}" };
        await users.CreateAsync(user, CorrectPassword);

        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        var factorId = Guid.NewGuid();
        var protectedSecret = new TotpSecretProtector(TotpKey, "v1").Protect(user.Id, factorId, secret);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor
        {
            Id = factorId,
            UserId = user.Id,
            ConfirmedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            KeyVersion = protectedSecret.KeyVersion,
            Nonce = protectedSecret.Nonce,
            Ciphertext = protectedSecret.Ciphertext,
            Tag = protectedSecret.Tag,
        });
        await db.SaveChangesAsync();
        return (users, user, secret);
    }

    private static string? Cookie(HttpContext context, string name)
    {
        var pair = context.Response.Headers.SetCookie
            .Select(value => value!.Split(';')[0])
            .FirstOrDefault(value => value.StartsWith(name + "=", StringComparison.Ordinal));
        return pair is null ? null : pair[(name.Length + 1)..];
    }
}

