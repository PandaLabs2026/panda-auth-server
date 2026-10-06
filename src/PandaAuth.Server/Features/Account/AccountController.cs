using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using PandaAuth.Shared;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;

namespace PandaAuth.Server.Features.Account;

[Route("~/account")]
public sealed class AccountController(
    UserService userManager,
    LoginSessionService signInManager,
    LoginRateLimiter loginRateLimiter,
    LoginAuditWriter loginAudit,
    IPasswordHasher passwordHasher,
    DummyPasswordHash dummyPasswordHash,
    IOptions<AuthOptions> authOptions,
    MfaService? mfa = null,
    LoginMfaChallengeService? loginMfaChallenges = null,
    SecurityEventWriter? securityEvents = null) : Controller
{
    /// <summary>dummy 校验用的占位用户；Argon2 校验只依赖哈希与口令，不读取该实例的状态。</summary>
    private static readonly PandaUser DummyUser = new();

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        // 已认证用户访问登录页：继续本地 returnUrl（SSO 授权续走）或落到账户中心 /me/。
        // auth 源根路径被 Caddy 指回 /account/login——无此重定向会让「登录成功」的用户
        // 落到 / 后又被弹回登录表单，形成死循环。
        if (User.Identity?.IsAuthenticated == true)
        {
            return LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl! : "/me/");
        }

        // 自助重置/改密（CredentialController）完成后跳转回来时带一次性提示。
        if (TempData["Notice"] is string notice)
        {
            ViewData["Notice"] = notice;
        }

        return View(new LoginViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers.UserAgent.ToString();
        var normalizedUserName = model.UserName.Trim();

        using var ipLease = loginRateLimiter.AttemptByIp(ipAddress);
        if (!ipLease.IsAcquired)
        {
            return ViewWithError("尝试过于频繁，请稍后再试。");
        }

        using var accountLease = loginRateLimiter.AttemptByAccount(normalizedUserName);
        if (!accountLease.IsAcquired)
        {
            return ViewWithError("尝试过于频繁，请稍后再试。");
        }

        var user = await userManager.FindByNameAsync(normalizedUserName);
        var succeeded = false;
        PandaUser? signedInUser = null;
        string? failureReason = "user_not_found";

        if (user is not null && user.Status != UserStatus.Active)
        {
            failureReason = "account_frozen";
            // 用户可见文案与「用户名或密码错误」完全一致：区分文案（冻结/锁定/口令）等于免费向
            // 撞库者确认账号存在。真实原因只落 login_logs（运维可辨），响应耗时仍与「用户不存在」
            // 一样支付一次等价哈希代价，避免各分支形成可枚举的耗时指纹。
            passwordHasher.Verify(dummyPasswordHash.Value, model.Password);
            await loginAudit.RecordAsync(BuildLog(), cancellationToken);
            return ViewWithError("用户名或密码错误。");
        }

        if (user is not null)
        {
            var result = await signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
            succeeded = result.Succeeded;
            signedInUser = result.User;
            if (result.RequiresMfaReconfiguration && result.User is not null)
            {
                // TwoFactorEnabled 只是「曾开启 MFA」的遗留标志；MfaService.MfaStatus 的口径是
                // 「标志开启且无活跃因子」才需重配置——两处真值源在此对齐：标志遗留但仍有活跃
                // 因子时清标志自愈，按正常（挑战/直登）路径继续；无因子才进重配置流。
                if (mfa is null || !await mfa.HasActiveFactorAsync(result.User.Id, cancellationToken))
                {
                    await signInManager.SignInForMfaReconfigurationAsync(HttpContext, result.User);
                    return LocalRedirect("/account/mfa/user/reconfigure");
                }

                result.User.TwoFactorEnabled = false;
                await userManager.UpdateAsync(result.User);
                // 该 outcome 的 Succeeded 为 false，但此路径密码已验证通过：改按成功继续，
                // 否则会被记成 not_allowed 并落回「用户名或密码错误」的死胡同。
                succeeded = true;
                signedInUser = result.User;
            }
            failureReason = succeeded ? null
                : result.IsLockedOut ? "locked_out"
                : result.IsNotAllowed ? "not_allowed"
                : "wrong_password";
        }
        else
        {
            // 时间侧信道拉平：用户不存在时同样付出一次 Argon2 代价（对固定 dummy 哈希校验一次），
            // 使两条路径耗时接近。否则「不存在的用户名」明显更快返回，响应内容再一致也可枚举账号。
            passwordHasher.Verify(dummyPasswordHash.Value, model.Password);
        }

        await loginAudit.RecordAsync(BuildLog(), cancellationToken);

        if (!succeeded)
        {
            // 同冻结分支：锁定与口令错误的用户可见文案不区分，真实原因只落 login_logs。
            return ViewWithError("用户名或密码错误。");
        }

        // 登录路径 MFA 挑战：开关开启且已有活跃因子时，签入前先要求第二因子（2026-09-30 拍板）。
        // 此时只签发自包含的 pending 挑战 cookie，不签发任何已认证身份。
        if (authOptions.Value.LoginMfa.Enabled &&
            mfa is not null && loginMfaChallenges is not null &&
            await mfa.HasActiveFactorAsync(signedInUser!.Id, cancellationToken))
        {
            loginMfaChallenges.Issue(HttpContext, signedInUser.Id, signedInUser.SecurityStamp ?? "");
            await RecordSecurityEventAsync("login.mfa_challenge_required", signedInUser.Id, cancellationToken);
            return Redirect($"/account/mfa/challenge?returnUrl={Uri.EscapeDataString(SafeReturnUrl(model.ReturnUrl))}");
        }

        await signInManager.SignInAsync(HttpContext, signedInUser!, isPersistent: false);
        return LocalRedirect(string.IsNullOrWhiteSpace(model.ReturnUrl) ? "/me/" : model.ReturnUrl);

        // returnUrl 无效/缺失时，MFA 挑战完成后的落点须与直登成功一致（/me/）：
        // 挑战页与断言端各自兜底，旧值 / 是公网形态下的死胡同（根路径被网关指回登录页）。
        string SafeReturnUrl(string? returnUrl)
            => Url.IsLocalUrl(returnUrl) ? returnUrl! : "/me/";

        IActionResult ViewWithError(string message)
        {
            ModelState.AddModelError(string.Empty, message);
            return View(model);
        }

        LoginLog BuildLog() => new()
        {
            UserId = user?.Id,
            UserName = normalizedUserName,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Succeeded = succeeded,
            FailureReason = failureReason,
        };
    }

    private Task RecordSecurityEventAsync(string eventType, string userId, CancellationToken cancellationToken)
        => securityEvents is null
            ? Task.CompletedTask
            : securityEvents.RecordAsync(new SecurityEventEntry(
                eventType,
                userId,
                userId,
                "user",
                userId,
                null,
                null,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString(),
                HttpContext.TraceIdentifier), cancellationToken);

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        // 登出后回登录页而非 /me/：me 未认证会被立刻 challenge 回登录页，多一跳无意义；
        // auth 源根路径（/）在公网形态由网关指回 /account/login，直接落登录表单路径最短。
        // Notice 经 TempData 一次性提示「已安全退出」，登录 GET 已渲染（见 Login 视图）。
        TempData["Notice"] = "已安全退出。";
        await signInManager.SignOutAsync(HttpContext);
        return Redirect("/account/login");
    }
}
