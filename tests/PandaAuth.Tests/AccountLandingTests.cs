using System.Security.Claims;
using System.Security.Cryptography;
using Fido2NetLib;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 登录/登出落点回归（PR#18 后续补完）：直登与 MFA 挑战完成后的默认落点是账户中心 /me/，
/// 登出回登录页并带一次性 Notice。根路径 / 在公网形态（如 auth.appliket.com）由网关指回
/// 登录页或直接 404，禁止再作为任何登录流程的落点或兜底。
/// </summary>
public class AccountLandingTests
{
    private const string CorrectPassword = "Strong!Pass123";
    private static readonly byte[] TotpKey = Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    [Fact]
    public async Task DirectLogin_WithoutReturnUrl_LandsOnMe()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        await users.CreateAsync(new PandaUser { UserName = "direct-landing" }, CorrectPassword);

        var controller = Controller(provider);
        var action = await controller.Login(
            new LoginViewModel { UserName = "direct-landing", Password = CorrectPassword }, CancellationToken.None);

        // 无 returnUrl 的直登必须落 /me/（PR#18 已改此处，本用例钉住防止回退到死胡同 /）。
        var redirect = Assert.IsType<LocalRedirectResult>(action);
        Assert.Equal("/me/", redirect.Url);
        Assert.NotNull(Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
    }

    [Fact]
    public async Task Logout_LandsOnLogin_AndNoticeSurvivesCookieRoundTripIntoLoginGet()
    {
        using var provider = TestUserStoreHost.Create();
        var controller = Controller(provider);
        controller.TempData = new TempDataDictionary(controller.HttpContext, new NullTempDataProvider());

        var action = await controller.Logout();

        // 登出落登录页（不是 /me/：me 未认证会被立刻 challenge 回登录页，多一跳无意义）。
        var redirect = Assert.IsType<RedirectResult>(action);
        Assert.Equal("/account/login", redirect.Url);
        // IDP 登录 cookie 以过期删除头清除。
        Assert.Equal(string.Empty, Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
        var notice = Assert.IsType<string>(controller.TempData["Notice"]);
        Assert.Equal("已安全退出。", notice);

        // TempData 的跨请求载体是 cookie：用真实 CookieTempDataProvider 走一轮序列化/反序列化，
        // 证明 Notice 能落进登出响应并被下一条登录 GET 读回渲染（而非仅在内存字典内自洽）。
        var tempData = CookieTempData(provider);
        var responseContext = new DefaultHttpContext();
        tempData.SaveTempData(responseContext, new Dictionary<string, object> { ["Notice"] = notice });
        var cookie = Assert.Single(responseContext.Response.Headers.SetCookie)!;
        var requestContext = new DefaultHttpContext { RequestServices = provider };
        requestContext.Request.Headers.Cookie = cookie.Split(';')[0];

        var loginGet = Controller(provider);
        loginGet.ControllerContext.HttpContext = requestContext;
        loginGet.TempData = new TempDataDictionary(requestContext, tempData);
        var view = Assert.IsType<ViewResult>(loginGet.Login(returnUrl: null));
        Assert.Equal("已安全退出。", Assert.IsType<string>(view.ViewData["Notice"]));
    }

    [Theory]
    [InlineData("/connect/authorize?client_id=portal-web", "/connect/authorize?client_id=portal-web")]
    [InlineData(null, "/me/")]
    [InlineData("https://evil.example/callback", "/me/")]
    public void AuthenticatedLoginGet_ContinuesLocalReturnUrl_OrLandsOnMe(string? returnUrl, string expected)
    {
        using var provider = TestUserStoreHost.Create();
        var controller = Controller(provider);
        controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "landing-user")], LoginSessionService.Scheme));

        var redirect = Assert.IsType<LocalRedirectResult>(controller.Login(returnUrl));

        // 本地 returnUrl 续走（SSO 授权续走），缺失或外站值一律落 /me/，绝不再回登录表单或 /。
        Assert.Equal(expected, redirect.Url);
    }

    [Fact]
    public async Task LoginMfaChallenge_WithoutReturnUrl_CarriesMeFallback_AndTotpAssertionLandsOnMe()
    {
        using var provider = TestUserStoreHost.Create(new AuthOptions
        {
            LoginMfa = new LoginMfaOptions { Enabled = true },
        });
        var (_, user, secret) = await SeedUserWithTotpFactorAsync(provider, "mfa-landing");

        // 密码成功且 LoginMfa 开启 + 有活跃因子：不签入，重定向挑战页且 returnUrl 兜底为 /me/。
        var login = Controller(provider, withMfa: true);
        var challengeRedirect = Assert.IsType<RedirectResult>(await login.Login(
            new LoginViewModel { UserName = user.UserName!, Password = CorrectPassword }, CancellationToken.None));
        Assert.Equal("/account/mfa/challenge?returnUrl=%2Fme%2F", challengeRedirect.Url);
        Assert.Null(Cookie(login.HttpContext, "PandaAuth.Login.v2"));
        var pendingCookie = Cookie(login.HttpContext, LoginMfaChallengeService.CookieName);
        Assert.NotNull(pendingCookie);

        // 挑战页 GET：returnUrl 缺失与非本地值的兜底都必须是 /me/。
        var context = ChallengeContext(provider, pendingCookie);
        Assert.Equal("/me/", (await ChallengeModelAsync(provider, context, returnUrl: null)).ReturnUrl);
        Assert.Equal("/me/", (await ChallengeModelAsync(provider, context, returnUrl: "https://evil.example/cb")).ReturnUrl);

        // TOTP 断言成功（不再带 returnUrl）落 /me/。
        var assertion = ChallengeController(provider, context);
        var landed = Assert.IsType<LocalRedirectResult>(await assertion.AssertTotp(
            new LoginMfaChallengeTotpRequest { Code = TotpCode(secret) }, CancellationToken.None));
        Assert.Equal("/me/", landed.Url);
    }

    /// <summary>
    /// 登录连续失败 5 次→锁定的端到端回归：第 5 次失败即触发锁定，锁定期内即使口令正确也被拒；
    /// login_logs 逐次记录 failureReason，锁定次起为 locked_out。用户可见文案按当前行为钉住
    /// （后续 PR 统一文案时同步更新断言）。
    /// </summary>
    [Fact]
    public async Task FiveConsecutiveFailures_LockAccountWithLockedOutAuditAndUserMessage()
    {
        var options = new AuthOptions();
        // 抬高 IP/账号限流阈值：本用例聚焦 AccessFailedCount>=5 的账号锁定，别让固定窗口限流先挡住第 6 次尝试。
        options.RateLimit.IpPerMinute = 30;
        options.RateLimit.AccountPerMinute = 30;
        using var provider = TestUserStoreHost.Create(options);
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "lockout-target" };
        await users.CreateAsync(user, CorrectPassword);

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var view = Assert.IsType<ViewResult>(await Controller(provider).Login(
                new LoginViewModel { UserName = user.UserName!, Password = "Wrong!Pass123" }, CancellationToken.None));
            Assert.Equal(
                attempt < 5 ? "用户名或密码错误。" : "失败次数过多，账号已临时锁定，请稍后再试。",
                ViewError(view));
        }

        // 锁定未过期时，正确口令也必须被拒（锁定检查先决于口令结果）。
        var lockedView = Assert.IsType<ViewResult>(await Controller(provider).Login(
            new LoginViewModel { UserName = user.UserName!, Password = CorrectPassword }, CancellationToken.None));
        Assert.Equal("失败次数过多，账号已临时锁定，请稍后再试。", ViewError(lockedView));

        var locked = await provider.GetRequiredService<UserService>().FindByNameAsync(user.UserName!);
        Assert.NotNull(locked!.LockoutEnd);
        Assert.True(locked.LockoutEnd > DateTimeOffset.UtcNow, "lockout must outlive the failing sequence");

        var logs = await provider.GetRequiredService<PandaAuthDbContext>().LoginLogs
            .OrderBy(log => log.Id).ToListAsync();
        Assert.Equal(6, logs.Count);
        Assert.All(logs, log => Assert.False(log.Succeeded));
        Assert.All(logs.Take(4), log => Assert.Equal("wrong_password", log.FailureReason));
        Assert.Equal("locked_out", logs[4].FailureReason);
        Assert.Equal("locked_out", logs[5].FailureReason);
    }

    // ---- 基建（与 LoginMfaChallengeTests 同构：真实服务 + InMemory 存储，逐请求新建控制器） ----

    private static AccountController Controller(ServiceProvider provider, bool withMfa = false)
    {
        var controller = TestUserStoreHost.CreateAccountController(
            provider,
            provider.GetRequiredService<IPasswordHasher>(),
            withMfa ? MfaService(provider) : null,
            withMfa ? provider.GetRequiredService<LoginMfaChallengeService>() : null,
            withMfa ? provider.GetRequiredService<SecurityEventWriter>() : null);
        // 登录 GET 会读 TempData：手工注入字典，避免依赖 MVC 管道的 TempData 初始化。
        controller.TempData = new TempDataDictionary(controller.HttpContext, new NullTempDataProvider());
        return controller;
    }

    private static string ViewError(ViewResult view)
        => view.ViewData.ModelState[string.Empty]!.Errors.Single().ErrorMessage;

    /// <summary>取 MVC 管道实际使用的 TempData provider（AddControllersWithViews 注册的 Cookie 实现），
    /// 序列化细节（serializer/cookie 名）与其保持一致，round-trip 才等价于真实浏览器往返。</summary>
    private static ITempDataProvider CookieTempData(ServiceProvider provider)
        => provider.GetRequiredService<ITempDataProvider>();

    private static MfaService MfaService(ServiceProvider provider) => new(
        provider.GetRequiredService<PandaAuthDbContext>(),
        provider.GetRequiredService<UserService>(),
        new TotpFactorService(
            provider.GetRequiredService<PandaAuthDbContext>(),
            new TotpSecretProtector(TotpKey, "v1"),
            TimeProvider.System),
        provider.GetRequiredService<LoginSessionService>(),
        TimeProvider.System);

    private static LoginMfaChallengeController ChallengeController(
        ServiceProvider provider, DefaultHttpContext context)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        return new LoginMfaChallengeController(
            provider.GetRequiredService<UserService>(),
            MfaService(provider),
            new WebAuthnCeremonyService(
                new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                db,
                new MfaChallengeStore(db, TimeProvider.System)),
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

    private static async Task<LoginMfaChallengeViewModel> ChallengeModelAsync(
        ServiceProvider provider, DefaultHttpContext context, string? returnUrl)
    {
        var view = Assert.IsType<ViewResult>(
            await ChallengeController(provider, context).Index(returnUrl, CancellationToken.None));
        return Assert.IsType<LoginMfaChallengeViewModel>(view.Model);
    }

    private static DefaultHttpContext ChallengeContext(ServiceProvider provider, string pendingCookie)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        context.Request.Headers.Cookie = $"{LoginMfaChallengeService.CookieName}={pendingCookie}";
        return context;
    }

    private static async Task<(UserService Users, PandaUser User, byte[] Secret)> SeedUserWithTotpFactorAsync(
        ServiceProvider provider, string userName)
    {
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = $"{userName}-{Guid.NewGuid():N}" };
        await users.CreateAsync(user, CorrectPassword);

        var secret = RandomNumberGenerator.GetBytes(20);
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

    /// <summary>标准 RFC 6238（SHA1/30s/6 位）生成当前验证码——独立于生产 TotpVerifier 实现，互为印证。</summary>
    private static string TotpCode(byte[] secret)
    {
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> counter = stackalloc byte[8];
        for (var index = counter.Length - 1; index >= 0; index--)
        {
            counter[index] = (byte)step;
            step >>= 8;
        }
        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) |
                     (hash[offset + 1] << 16) |
                     (hash[offset + 2] << 8) |
                     hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string? Cookie(HttpContext context, string name)
    {
        var pair = context.Response.Headers.SetCookie
            .Select(value => value!.Split(';')[0])
            .FirstOrDefault(value => value.StartsWith(name + "=", StringComparison.Ordinal));
        return pair is null ? null : pair[(name.Length + 1)..];
    }
}
