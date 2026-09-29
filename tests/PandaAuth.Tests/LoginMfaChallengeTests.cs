using System.Security.Claims;
using System.Security.Cryptography;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
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
/// 登录路径 MFA 挑战（2026-09-30 拍板）契约测试：开关关闭时行为零变化；
/// 开启后密码成功≠签入，必须经 pending 挑战 cookie 完成第二因子；断言成功才会诞生携带 amr 的会话。
/// </summary>
public class LoginMfaChallengeTests
{
    private static readonly byte[] TotpKey = Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    [Fact]
    public async Task EnabledWithActiveFactor_IssuesPendingChallengeInsteadOfSignIn()
    {
        using var provider = Host(loginMfaEnabled: true);
        var (users, user, _) = await SeedUserWithTotpFactorAsync(provider);

        var controller = AccountController(provider, withMfa: true);
        var action = await controller.Login(
            new LoginViewModel { UserName = user.UserName!, Password = "Strong!Pass123" }, CancellationToken.None);

        // 密码成功但未签入：只签发 pending 挑战 cookie，重定向挑战页；IDP 登录 cookie 必须缺席。
        var redirect = Assert.IsType<RedirectResult>(action);
        Assert.StartsWith("/account/mfa/challenge?returnUrl=", redirect.Url, StringComparison.Ordinal);
        Assert.NotNull(Cookie(controller.HttpContext, LoginMfaChallengeService.CookieName));
        Assert.Null(Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
        Assert.Contains(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents,
            logEvent => logEvent.EventType == "login.mfa_challenge_required" && logEvent.UserId == user.Id);
    }

    [Theory]
    [InlineData(true, false)]  // 开启但无活跃因子：直通签入（挑战只对有因子用户生效）
    [InlineData(false, true)]  // 关闭：既有行为零变化（回归锚点）
    public async Task NoFactorOrDisabled_SignsInDirectly(bool enabled, bool seedFactor)
    {
        using var provider = Host(enabled);
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member-login" };
        await users.CreateAsync(user, "Strong!Pass123");
        if (seedFactor)
        {
            var db = provider.GetRequiredService<PandaAuthDbContext>();
            db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
            {
                UserId = user.Id, CredentialId = [1, 2, 3], PublicKeyCose = [4, 5, 6],
            });
            await db.SaveChangesAsync();
        }

        var controller = AccountController(provider, withMfa: true);
        var action = await controller.Login(
            new LoginViewModel { UserName = user.UserName!, Password = "Strong!Pass123" }, CancellationToken.None);

        Assert.IsType<LocalRedirectResult>(action);
        Assert.Null(Cookie(controller.HttpContext, LoginMfaChallengeService.CookieName));
        Assert.NotNull(Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
    }

    [Fact]
    public void PendingChallengeCookie_RejectsTamperedPayloadAndExpiry()
    {
        var time = new StubTimeProvider(DateTimeOffset.UtcNow);
        var service = new LoginMfaChallengeService(EphemeralProtection(), time);
        var context = new DefaultHttpContext();
        service.Issue(context, Guid.NewGuid().ToString(), "stamp");

        var payload = Cookie(context, LoginMfaChallengeService.CookieName)!;

        var fresh = new DefaultHttpContext();
        fresh.Request.Headers.Cookie = $"{LoginMfaChallengeService.CookieName}={payload}";
        Assert.NotNull(service.Read(fresh));

        var tampered = new DefaultHttpContext();
        tampered.Request.Headers.Cookie =
            $"{LoginMfaChallengeService.CookieName}={payload[..^2]}{(payload[^2] == 'A' ? "B" : "A")}{payload[^1]}";
        Assert.Null(service.Read(tampered));

        var forged = new DefaultHttpContext();
        forged.Request.Headers.Cookie = $"{LoginMfaChallengeService.CookieName}=not-a-protected-payload";
        Assert.Null(service.Read(forged));

        time.Advance(LoginMfaChallengeService.Lifetime + TimeSpan.FromSeconds(1));
        var expired = new DefaultHttpContext();
        expired.Request.Headers.Cookie = $"{LoginMfaChallengeService.CookieName}={payload}";
        Assert.Null(service.Read(expired));
    }

    [Fact]
    public async Task ChallengePage_WithoutPendingCookie_RedirectsToLogin()
    {
        using var provider = Host(true);
        var controller = ChallengeController(provider);

        var action = await controller.Index(null, CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(action);
        Assert.Equal("/account/login", redirect.Url);
    }

    [Fact]
    public async Task TotpAssertion_ValidCode_SignsInWithAmrAndClearsPendingChallenge()
    {
        using var provider = Host(true);
        var (users, user, secret) = await SeedUserWithTotpFactorAsync(provider);

        var context = ChallengeContext(provider, user);
        var controller = ChallengeController(provider, context);
        var action = await controller.AssertTotp(
            new LoginMfaChallengeTotpRequest { Code = TotpCode(secret), ReturnUrl = "/connect/authorize" },
            CancellationToken.None);

        // 断言成功：重定向 returnUrl，登录 cookie 自诞生携带 amr=totp，pending 挑战清除。
        var redirect = Assert.IsType<LocalRedirectResult>(action);
        Assert.Equal("/connect/authorize", redirect.Url);
        var loginCookie = Cookie(context, "PandaAuth.Login.v2");
        Assert.NotNull(loginCookie);
        // pending 挑战以过期删除头清除（Set-Cookie 空值）。
        Assert.Equal(string.Empty, Cookie(context, LoginMfaChallengeService.CookieName));

        using var scope = provider.CreateScope();
        var verification = LoginContext(scope.ServiceProvider, $"PandaAuth.Login.v2={loginCookie}");
        var ticket = await verification.AuthenticateAsync(LoginSessionService.Scheme);
        Assert.True(ticket.Succeeded, ticket.Failure?.Message ?? "authentication failed without message");
        Assert.Equal(MfaClaimTypes.Totp, ticket.Principal!.FindFirst(MfaClaimTypes.Method)!.Value);
        Assert.NotNull(ticket.Principal.FindFirst(MfaClaimTypes.VerifiedAt));

        // 令牌链闭环：挑战诞生的会话作为 mfaSource 铸出的 OIDC 主体必须携带 amr/panda_mfa_at
        // （AuthorizationController 发码走同一 CreatePrincipalAsync 路径）。
        var authorization = TestUserStoreHost.CreateAuthorizationController(provider);
        var tokenPrincipal = await authorization.CreatePrincipalAsync(
            (await provider.GetRequiredService<UserService>().FindByIdAsync(user.Id))!,
            [OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId],
            ticket.Principal!);
        Assert.Equal(MfaClaimTypes.Totp, tokenPrincipal.FindFirst(MfaClaimTypes.Method)!.Value);
        Assert.NotNull(tokenPrincipal.FindFirst(MfaClaimTypes.VerifiedAt));

        var db = provider.GetRequiredService<PandaAuthDbContext>();
        Assert.Contains(db.SecurityEvents, logEvent =>
            logEvent.EventType == "login.mfa_challenge_succeeded" &&
            logEvent.UserId == user.Id &&
            logEvent.AuthenticationMethod == MfaClaimTypes.Totp);
    }

    [Fact]
    public async Task TotpAssertion_InvalidCode_DoesNotSignInAndRecordsFailure()
    {
        using var provider = Host(true);
        var (users, user, secret) = await SeedUserWithTotpFactorAsync(provider);

        var context = ChallengeContext(provider, user);
        var controller = ChallengeController(provider, context);
        var action = await controller.AssertTotp(
            new LoginMfaChallengeTotpRequest { Code = "000000" }, CancellationToken.None);

        var view = Assert.IsType<ViewResult>(action);
        Assert.Equal("Index", view.ViewName);
        Assert.Null(Cookie(context, "PandaAuth.Login.v2"));
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        Assert.Contains(db.SecurityEvents, logEvent =>
            logEvent.EventType == "login.mfa_challenge_failed" && logEvent.UserId == user.Id);
    }

    [Fact]
    public async Task TotpAssertion_IsRateLimitedPerUser()
    {
        var options = new AuthOptions();
        options.LoginMfa.Enabled = true;
        options.RateLimit.MfaChallengeAccountPerMinute = 2;
        using var provider = Host(options);
        var (users, user, secret) = await SeedUserWithTotpFactorAsync(provider);

        var context = ChallengeContext(provider, user);
        var controller = ChallengeController(provider, context);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await controller.AssertTotp(new LoginMfaChallengeTotpRequest { Code = "000000" }, CancellationToken.None);
        }

        // 第 3 次尝试即使携带正确验证码也被限流拒绝——TOTP 六位码可暴力尝试，必须先于校验拒绝。
        var action = await controller.AssertTotp(
            new LoginMfaChallengeTotpRequest { Code = TotpCode(secret) }, CancellationToken.None);
        Assert.IsType<ViewResult>(action);
        Assert.Null(Cookie(context, "PandaAuth.Login.v2"));
    }

    [Fact]
    public async Task TotpAssertion_AfterPasswordResetDuringChallengeWindow_FailsClosed()
    {
        using var provider = Host(true);
        var (users, user, secret) = await SeedUserWithTotpFactorAsync(provider);

        var context = ChallengeContext(provider, user);
        // 挑战窗口内安全戳轮换（如管理员重置密码）：pending 挑战必须失效，正确验证码也不得签入。
        await users.ReplacePasswordAsync(user, "Rotated!Pass123");

        var controller = ChallengeController(provider, context);
        var action = await controller.AssertTotp(
            new LoginMfaChallengeTotpRequest { Code = TotpCode(secret) }, CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(action);
        Assert.Equal("/account/login", redirect.Url);
        Assert.Null(Cookie(context, "PandaAuth.Login.v2"));
    }

    [Fact]
    public async Task PasskeyChallenge_BeginRequiresPendingCookie()
    {
        using var provider = Host(true);
        var (users, user, secret) = await SeedUserWithTotpFactorAsync(provider);

        var controller = ChallengeController(provider);
        var action = await controller.BeginPasskeyAssertion(CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(action);
    }

    [Fact]
    public async Task PasskeyChallenge_BeginWithPendingCookie_ReturnsCeremonyForActiveCredentials()
    {
        using var provider = Host(true);
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "passkey-login" };
        await users.CreateAsync(user, "Strong!Pass123");
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id, CredentialId = [9, 9, 9], PublicKeyCose = [4, 5, 6],
        });
        await db.SaveChangesAsync();

        var context = ChallengeContext(provider, user);
        var controller = ChallengeController(provider, context);
        var action = await controller.BeginPasskeyAssertion(CancellationToken.None);

        var json = Assert.IsType<JsonResult>(action);
        Assert.NotNull(json.Value);
    }

    [Fact]
    public async Task PasskeyChallenge_CompleteWithUnknownCeremony_FailsClosedAndRecordsFailure()
    {
        using var provider = Host(true);
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "passkey-unknown" };
        await users.CreateAsync(user, "Strong!Pass123");
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id, CredentialId = [9, 9, 9], PublicKeyCose = [4, 5, 6],
        });
        await db.SaveChangesAsync();

        var context = ChallengeContext(provider, user);
        var controller = ChallengeController(provider, context);
        var action = await controller.CompletePasskeyAssertion(
            new CompletePasskeyAssertionRequest
            {
                CeremonyId = Guid.NewGuid(),
                Response = new AuthenticatorAssertionRawResponse { RawId = [9, 9, 9] },
            },
            CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(action);
        Assert.Null(Cookie(context, "PandaAuth.Login.v2"));
        Assert.Contains(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents, logEvent =>
            logEvent.EventType == "login.mfa_challenge_failed" && logEvent.AuthenticationMethod == MfaClaimTypes.WebAuthn);
    }

    // ---- 基建 ----

    private static ServiceProvider Host(bool loginMfaEnabled)
        => Host(new AuthOptions { LoginMfa = new LoginMfaOptions { Enabled = loginMfaEnabled } });

    private static ServiceProvider Host(AuthOptions options) => TestUserStoreHost.Create(options);

    private static AccountController AccountController(ServiceProvider provider, bool withMfa)
        => TestUserStoreHost.CreateAccountController(
            provider,
            provider.GetRequiredService<IPasswordHasher>(),
            withMfa ? MfaService(provider) : null,
            withMfa ? provider.GetRequiredService<LoginMfaChallengeService>() : null,
            withMfa ? provider.GetRequiredService<SecurityEventWriter>() : null);

    private static MfaService MfaService(ServiceProvider provider)
        => new(
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<UserService>(),
            TotpFactors(provider),
            provider.GetRequiredService<LoginSessionService>(),
            TimeProvider.System);

    private static TotpFactorService TotpFactors(ServiceProvider provider)
        => new(
            provider.GetRequiredService<PandaAuthDbContext>(),
            new TotpSecretProtector(TotpKey, "v1"),
            TimeProvider.System);

    private static LoginMfaChallengeController ChallengeController(
        ServiceProvider provider, DefaultHttpContext? context = null)
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
                context ?? new DefaultHttpContext { RequestServices = provider },
                new Microsoft.AspNetCore.Routing.RouteData(),
                new Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor())),
        };
    }

    /// <summary>签发 pending 挑战（模拟密码已验证）并把 cookie 装进请求上下文。</summary>
    private static DefaultHttpContext ChallengeContext(ServiceProvider provider, PandaUser user)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        provider.GetRequiredService<LoginMfaChallengeService>()
            .Issue(context, user.Id, user.SecurityStamp ?? "");
        var payload = Cookie(context, LoginMfaChallengeService.CookieName)!;
        var challenge = new DefaultHttpContext { RequestServices = provider };
        challenge.Request.Scheme = "https";
        challenge.Request.Headers.Cookie = $"{LoginMfaChallengeService.CookieName}={payload}";
        return challenge;
    }

    private static async Task<(UserService Users, PandaUser User, byte[] Secret)> SeedUserWithTotpFactorAsync(
        ServiceProvider provider)
    {
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = $"totp-login-{Guid.NewGuid():N}" };
        await users.CreateAsync(user, "Strong!Pass123");

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

    private static DefaultHttpContext LoginContext(IServiceProvider provider, string cookie)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        context.Request.Headers.Cookie = cookie;
        return context;
    }

    private static Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider EphemeralProtection() => new();

    private sealed class StubTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now += delta;
    }
}
