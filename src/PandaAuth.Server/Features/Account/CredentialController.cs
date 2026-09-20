using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Shared;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Features.Account;

/// <summary>
/// 自助凭据管理（server 0.4 第一批）：忘记密码（邮箱验证码重置）与已登录改密。
/// 与登录共用 ~/account 前缀、限流器与审计风格；三条匿名/认证路径全部有防枚举与频控。
/// </summary>
[Route("~/account")]
public sealed class CredentialController(
    UserService userManager,
    LoginSessionService signInManager,
    LoginRateLimiter loginRateLimiter,
    OtpService otpService,
    IEmailSender emailSender,
    ITokenRevoker tokenRevoker,
    ILogger<CredentialController> logger) : Controller
{
    /// <summary>忘记密码：输入邮箱请求验证码。防枚举——存在与否都走同一签发路径、回同一句话。</summary>
    [HttpGet("forgot-password")]
    public IActionResult ForgotPassword(string? returnUrl = null)
    {
        return View(new ForgotPasswordViewModel { ReturnUrl = returnUrl });
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
        using var ipLease = loginRateLimiter.AttemptByIp(HttpContext.Connection.RemoteIpAddress?.ToString());
        if (!ipLease.IsAcquired)
        {
            // 限流命中与成功发出同形（同一跳转、同一提示），不暴露差异。
            TempData["ResetEmail"] = email;
            TempData["ReturnUrl"] = model.ReturnUrl;
            TempData["Info"] = "如果该邮箱存在已注册账号，验证码已发送，请查收（5 分钟内有效）。";
            return RedirectToAction(nameof(ResetPassword));
        }

        try
        {
            // 无论账号是否存在都先签发（计数 + 写库路径完全一致，消除时序侧信道）；
            // 仅对真实存在的 Active 账号真正发送。验证码明文只经过内存与发送调用，不落任何日志。
            var code = await otpService.IssueAsync(email, cancellationToken);
            var user = await userManager.FindByEmailAsync(email);
            if (user is not null && user.Status == UserStatus.Active)
            {
                await emailSender.SendVerificationCodeAsync(email, code, cancellationToken);
                logger.LogInformation("忘记密码验证码已发送 userId={UserId}", user.Id);
            }
        }
        catch (OtpRateLimitedException)
        {
            // 吞掉差异：频控命中与成功发出对调用方完全同形。
        }

        // 中性完成后直接带邮箱进重置页——验证码输入框在那里（PRG：刷新/回退不重复发信）。
        // ReturnUrl（发起方授权上下文）随 TempData 与表单隐藏字段双层携带，重置完成后回原发起方。
        TempData["ResetEmail"] = email;
        TempData["ReturnUrl"] = model.ReturnUrl;
        TempData["Info"] = "如果该邮箱存在已注册账号，验证码已发送，请查收（5 分钟内有效）。";
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

        return View(new ResetPasswordViewModel { Email = email, ReturnUrl = TempData["ReturnUrl"] as string });
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

        // 先校验验证码（含 5 败锁定与双频控），再找账号——验证码对不存在的邮箱也签发过（防枚举），
        // 但只有真实账号发出的码才会到达用户邮箱。
        var outcome = await otpService.VerifyAsync(email, model.Code, cancellationToken);
        if (outcome != OtpVerifyOutcome.Success)
        {
            return ViewWithError(outcome == OtpVerifyOutcome.Locked
                ? "验证失败次数过多，请 15 分钟后再试。"
                : "验证码错误或已过期。");
        }

        var user = await userManager.FindByEmailAsync(email);
        if (user is null || user.Status != UserStatus.Active)
        {
            // 验证码正确但账号不可用（不存在/冻结/注销）：不暴露具体状态。
            return ViewWithError("验证码错误或已过期。");
        }

        var (changed, error) = await ReplacePasswordAsync(user, model.NewPassword);
        if (!changed)
        {
            return ViewWithError(error ?? "新密码不合规。");
        }

        await userManager.UpdateSecurityStampAsync(user);
        await tokenRevoker.RevokeUserTokensAsync(user.Id, cancellationToken: cancellationToken);
        logger.LogInformation("用户通过邮箱验证码自助重置密码 userId={UserId}", user.Id);

        TempData["Notice"] = "密码已重置，请使用新密码登录。";
        return RedirectToAction("Login", "Account", new { returnUrl = model.ReturnUrl });
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
