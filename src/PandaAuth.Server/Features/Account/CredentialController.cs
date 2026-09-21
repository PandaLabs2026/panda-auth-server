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
            return ViewWithError("尝试过于频繁，请稍后再试。");
        }

        var outcome = await verification.ConsumePasswordResetAsync(
            email, model.Token, model.NewPassword, cancellationToken);
        if (!outcome.Succeeded)
        {
            return ViewWithError(outcome.Error == AccountVerificationError.PasswordPolicy
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
        if (!result.Succeeded) return ViewWithError("令牌错误、已使用或已过期。");
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
        if (!user.EmailConfirmed) return ViewWithError("请先确认当前邮箱。");
        var check = await signInManager.CheckPasswordSignInAsync(user, model.CurrentPassword, lockoutOnFailure: true);
        if (!check.Succeeded) return ViewWithError("当前密码不正确。");
        var outcome = await verification.BeginEmailChangeAsync(check.User!.Id, model.NewEmail, cancellationToken);
        if (!outcome.Succeeded) return ViewWithError("无法变更邮箱，请检查目标地址。");
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
        if (!outcome.Succeeded) return ViewWithError("令牌错误、已使用或已过期。");
        await tokenRevoker.RevokeUserTokensAsync(user.Id, cancellationToken: cancellationToken);
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
        if (!user.EmailConfirmed) return ViewWithError("请先确认当前邮箱。");
        var (changed, error) = await ReplacePasswordAsync(user, model.NewPassword);
        if (!changed)
        {
            ModelState.AddModelError(string.Empty, error ?? "新密码不合规。");
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
    /// 移除旧密码并写入新密码（走完整密码策略校验）。校验失败时回滚旧哈希——
    /// 不回滚会把账号锁死在「无密码」状态（与管理端重置同一处实证结论）。
    /// 安全戳一并回滚：AddPasswordAsync 内部已轮换，不还原会让一次失败的改密
    /// 仍然踹掉目标既有 Cookie 会话（与管理端重置同一口径）。
    /// </summary>
    private async Task<(bool Changed, string? Error)> ReplacePasswordAsync(PandaUser user, string newPassword)
    {
        var add = await userManager.ReplacePasswordAsync(user, newPassword);
        if (!add.Succeeded)
        {
            return (false, string.Join("；", add.Errors.Select(error => error.Description)));
        }

        return (true, null);
    }

    private IActionResult ViewWithError(string message)
    {
        ModelState.AddModelError(string.Empty, message);
        return View();
    }

    private static string NormalizeLocalReturnUrl(string? returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
            && returnUrl.StartsWith('/')
            && !returnUrl.StartsWith("//")
            && !returnUrl.StartsWith("/\\")
            ? returnUrl
            : "/";
}
