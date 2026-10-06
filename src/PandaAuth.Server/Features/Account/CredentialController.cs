using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Shared;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Features.Account;

/// <summary>
/// 自助凭据管理：邮箱确认、更换邮箱、密码恢复与已登录改密。
/// 与登录共用 ~/account 前缀、限流器与审计风格；三条匿名/认证路径全部有防枚举与频控。
/// </summary>
[Route("~/account")]
public sealed class CredentialController(
    UserService userManager,
    LoginSessionService signInManager,
    LoginRateLimiter loginRateLimiter,
    AccountVerificationService verification,
    IEmailSender emailSender,
    ITokenRevoker tokenRevoker,
    SecurityEventWriter securityEvents,
    SessionSecurityService sessionSecurity,
    IPwnedPasswordChecker pwnedPasswords,
    ILogger<CredentialController> logger) : Controller
{
    /// <summary>忘记密码：存在与否都走同一签发路径、回同一句话。</summary>
    [HttpGet("forgot-password")]
    public IActionResult ForgotPassword(string? returnUrl = null)
    {
        return View(new ForgotPasswordViewModel { ReturnUrl = NormalizeLocalReturnUrl(returnUrl) });
    }

    [HttpPost("forgot-password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var email = model.Email.Trim();
        var returnUrl = NormalizeLocalReturnUrl(model.ReturnUrl);
        using var ipLease = loginRateLimiter.AttemptByIp(HttpContext.Connection.RemoteIpAddress?.ToString());
        if (!ipLease.IsAcquired)
        {
            // 限流命中与成功发出同形（同一跳转、同一提示），不暴露差异。
            TempData["ResetEmail"] = email;
            TempData["ReturnUrl"] = returnUrl;
            TempData["Info"] = RecoveryMessage;
            return RedirectToAction(nameof(ResetPassword));
        }

        await verification.BeginPasswordResetAsync(email, cancellationToken);

        // 中性完成后直接带邮箱进重置页（PRG：刷新/回退不重复发信）。
        // ReturnUrl（发起方授权上下文）随 TempData 与表单隐藏字段双层携带，重置完成后回原发起方。
        TempData["ResetEmail"] = email;
        TempData["ReturnUrl"] = returnUrl;
        TempData["Info"] = RecoveryMessage;
        return RedirectToAction(nameof(ResetPassword));
    }

    [HttpGet("reset-password")]
    public IActionResult ResetPassword()
    {
        var email = TempData["ResetEmail"] as string ?? string.Empty;
        if (TempData["Info"] is string info)
        {
            ViewData["Info"] = info;
        }

        return View(new ResetPasswordViewModel { Email = email, ReturnUrl = NormalizeLocalReturnUrl(TempData["ReturnUrl"] as string) });
    }

    [HttpPost("reset-password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var email = model.Email.Trim();
        using var ipLease = loginRateLimiter.AttemptByIp(HttpContext.Connection.RemoteIpAddress?.ToString());
        if (!ipLease.IsAcquired)
        {
            return ViewWithError(model, "尝试过于频繁，请稍后再试。");
        }

        // 泄露密码检测在令牌消费之前：命中即拒绝且不烧掉一次性令牌。
        var pwned = await pwnedPasswords.CheckAsync(model.NewPassword, cancellationToken);
        if (pwned.Rejected)
        {
            return ViewWithError(model, pwned.Outcome == PwnedPasswordOutcome.Breached
                ? "该密码出现在已知泄露库中，请更换新密码。"
                : "暂时无法核验密码安全性，请稍后再试。");
        }

        var outcome = await verification.ConsumePasswordResetAsync(
            email, model.Token, model.NewPassword, cancellationToken);
        if (!outcome.Succeeded)
        {
            return ViewWithError(model, outcome.Error == AccountVerificationError.PasswordPolicy
                ? "新密码不合规。"
                : "令牌错误、已使用或已过期。");
        }

        await tokenRevoker.RevokeUserTokensAsync(outcome.SecurityEvent!.SubjectId, cancellationToken: cancellationToken);
        await securityEvents.RecordAsync(new SecurityEventEntry(
            EventType: "user.password_reset",
            UserId: outcome.SecurityEvent.SubjectId,
            ActorUserId: null,
            TargetType: "user",
            TargetId: outcome.SecurityEvent.SubjectId,
            AuthenticationMethod: "email_token",
            Metadata: new { source = "forgot_password" },
            IpAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: Request.Headers.UserAgent.ToString(),
            CorrelationId: HttpContext.TraceIdentifier), cancellationToken);
        logger.LogInformation("用户通过邮箱恢复重置密码 userId={UserId}", outcome.SecurityEvent.SubjectId);

        // 重置成功通知（尽力而为）：账号持有人有权知道凭据刚被换过——受害者（令牌被钓鱼/邮箱被劫持）
        // 凭此接管。通知失败只记日志：重置本身已完成，不能因通道故障回滚或卡住流程。
        try
        {
            await emailSender.SendPasswordResetNoticeAsync(email, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(exception, "密码重置通知发送失败 email={Email}", email);
        }

        TempData["Notice"] = "密码已重置，请使用新密码登录。";
        return RedirectToAction("Login", "Account", new { returnUrl = NormalizeLocalReturnUrl(model.ReturnUrl) });
    }

    private const string RecoveryMessage = "如果该邮箱存在可恢复的账号，恢复令牌已发送，请查收（20 分钟内有效）。";

    [Authorize]
    [HttpGet("confirm-email")]
    public IActionResult ConfirmEmail() => View(new ConfirmEmailViewModel());

    [Authorize]
    [HttpPost("send-email-confirmation")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendEmailConfirmation(CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        await verification.BeginEmailConfirmationAsync(user.Id, cancellationToken);
        TempData["Info"] = "如果账号邮箱尚未确认，确认令牌已发送。";
        return RedirectToAction(nameof(ConfirmEmail));
    }

    [Authorize]
    [HttpPost("confirm-email")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return View(model);
        var user = await userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        var result = await verification.ConsumeEmailConfirmationAsync(user.Id, model.Token, cancellationToken);
        if (!result.Succeeded) return ViewWithError(model, "令牌错误、已使用或已过期。");
        TempData["Notice"] = "邮箱已确认。";
        return RedirectToAction("Login", "Account");
    }

    [Authorize]
    [HttpGet("change-email")]
    public IActionResult ChangeEmail(string? returnUrl = null)
        => View(new ChangeEmailViewModel { ReturnUrl = NormalizeLocalReturnUrl(returnUrl) });

    [Authorize]
    [HttpPost("change-email")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangeEmail(ChangeEmailViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return View(model);
        var user = await userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        if (!user.EmailConfirmed) return ViewWithError(model, "请先确认当前邮箱。");
        var check = await signInManager.CheckPasswordSignInAsync(user, model.CurrentPassword, lockoutOnFailure: true);
        if (!check.Succeeded) return ViewWithError(model, "当前密码不正确。");
        var outcome = await verification.BeginEmailChangeAsync(check.User!.Id, model.NewEmail, cancellationToken);
        if (!outcome.Succeeded) return ViewWithError(model, "无法变更邮箱，请检查目标地址。");
        TempData["PendingEmail"] = model.NewEmail;
        TempData["ReturnUrl"] = NormalizeLocalReturnUrl(model.ReturnUrl);
        return RedirectToAction(nameof(ConfirmEmailChange));
    }

    [Authorize]
    [HttpGet("confirm-email-change")]
    public IActionResult ConfirmEmailChange()
        => View(new ConfirmEmailChangeViewModel
        {
            NewEmail = TempData["PendingEmail"] as string ?? string.Empty,
            ReturnUrl = NormalizeLocalReturnUrl(TempData["ReturnUrl"] as string),
        });

    [Authorize]
    [HttpPost("confirm-email-change")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmEmailChange(
        ConfirmEmailChangeViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return View(model);
        var user = await userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        var oldEmail = user.Email;
        var outcome = await verification.ConsumeEmailChangeAsync(
            user.Id, model.NewEmail, model.Token, cancellationToken);
        if (!outcome.Succeeded) return ViewWithError(model, "令牌错误、已使用或已过期。");
        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: cancellationToken);
        await signInManager.SignOutAsync(HttpContext);
        if (!string.IsNullOrWhiteSpace(oldEmail))
        {
            var notice = EmailTemplates.EmailChangeNotice();
            try { await emailSender.SendAsync(oldEmail, notice.Subject, notice.Html, cancellationToken); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "旧邮箱变更通知发送失败 userId={UserId}", user.Id);
            }
        }
        return Redirect(NormalizeLocalReturnUrl(model.ReturnUrl));
    }

    /// <summary>自助改密（已登录，IDP Cookie）：旧密码验证 + 新密码；成功后吊销全部令牌并登出。</summary>
    [Authorize]
    [HttpGet("change-password")]
    public IActionResult ChangePassword(string? returnUrl = null)
    {
        return View(new ChangePasswordViewModel { ReturnUrl = NormalizeLocalReturnUrl(returnUrl) });
    }

    [Authorize]
    [HttpPost("change-password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model, CancellationToken cancellationToken)
    {
        model = new ChangePasswordViewModel
        {
            CurrentPassword = model.CurrentPassword,
            NewPassword = model.NewPassword,
            ReturnUrl = NormalizeLocalReturnUrl(model.ReturnUrl),
        };

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Challenge();
        }

        var check = await signInManager.CheckPasswordSignInAsync(user, model.CurrentPassword, lockoutOnFailure: true);
        if (!check.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "当前密码不正确。");
            return View(model);
        }

        // CheckPasswordSignInAsync can retry after a concurrency conflict. From this point on
        // every mutation must use its reloaded entity, not the pre-check instance.
        user = check.User!;
        if (!user.EmailConfirmed) return ViewWithError(model, "请先确认当前邮箱。");

        // 泄露密码检测：通过当前密码核验后、写入前执行。
        var pwned = await pwnedPasswords.CheckAsync(model.NewPassword, cancellationToken);
        if (pwned.Rejected)
        {
            ModelState.AddModelError(string.Empty, pwned.Outcome == PwnedPasswordOutcome.Breached
                ? "该密码出现在已知泄露库中，请更换新密码。"
                : "暂时无法核验密码安全性，请稍后再试。");
            return View(model);
        }

        // ReplacePasswordAsync（哈希+安全戳）经 UserService 的单次 SaveAsync 落库：
        // 策略校验在写库之前，失败即零变更；并发冲突路径由 UserService 内部重试消化。
        var changed = await userManager.ReplacePasswordAsync(user, model.NewPassword);
        if (!changed.Succeeded)
        {
            ModelState.AddModelError(string.Empty, string.Join("；", changed.Errors.Select(error => error.Description)));
            return View(model);
        }

        await userManager.UpdateSecurityStampAsync(user);
        await tokenRevoker.RevokeUserTokensAsync(user.Id, cancellationToken: cancellationToken);
        await signInManager.SignOutAsync(HttpContext);
        logger.LogInformation("用户自助修改密码 userId={UserId}（已吊销全部令牌并登出）", user.Id);

        TempData["Notice"] = "密码已修改，请使用新密码重新登录。";
        return RedirectToAction("Login", "Account");
    }

    /// <summary>
    /// 带 model 重渲染：保留已填字段（邮箱/ReturnUrl/令牌），用户改掉错误项即可重试，
    /// 不必整段重抄。令牌一并回显属可接受权衡——失败路径未消费令牌（消费即成功），
    /// 回显只省重抄、不放大滥用面；密码字段由 password 输入遮蔽。
    /// </summary>
    private IActionResult ViewWithError(object model, string message)
    {
        ModelState.AddModelError(string.Empty, message);
        return View(model);
    }

    private static string NormalizeLocalReturnUrl(string? returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
            && returnUrl.StartsWith('/')
            && !returnUrl.StartsWith("//")
            && !returnUrl.StartsWith("/\\")
            ? returnUrl
            : "/";
}
