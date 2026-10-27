using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Account;

/// <summary>
/// 登录路径 MFA 挑战入口（2026-09-30 拍板；AUTH-DELIVERY-002 起挑战因子=TOTP/恢复码）。
/// 用户身份只取自 pending 挑战 cookie——它在密码验证通过后、已有可验证因子时签发，
/// 且绑定签发时的安全戳；绝不接受请求体指定 subject。断言成功才签发携带
/// amr/panda_mfa_at 的 IDP 登录 cookie（SignInWithMfaAsync）。
/// Passkey 退役后，仅剩退役 passkey 且无恢复码的账号在此页明确阻塞（不静默降级为仅密码）。
/// </summary>
[AllowAnonymous]
[Route("~/account/mfa/challenge")]
public sealed class LoginMfaChallengeController(
    UserService users,
    MfaService mfa,
    LoginSessionService sessions,
    LoginMfaChallengeService challenges,
    LoginRateLimiter loginRateLimiter,
    SecurityEventWriter? securityEvents = null) : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index(string? returnUrl, CancellationToken cancellationToken)
    {
        var user = await ResolveChallengeUserAsync(cancellationToken);
        if (user is null)
        {
            return Redirect("/account/login");
        }
        var factors = await mfa.ListFactorsAsync(user.Id, cancellationToken);
        if (!factors.Any(factor => factor.Type == "totp"))
        {
            // 无可验证因子：退役 passkey 不构成挑战依据。有恢复码则保留自救通道；
            // 两者皆无则明确阻塞（静默放行等于把 MFA 账号降级为仅密码）。
            var hasRecoveryCodes = await HasRecoveryCodesAsync(user.Id, cancellationToken);
            if (!hasRecoveryCodes)
            {
                challenges.Clear(HttpContext);
                return View("Blocked", new LoginMfaChallengeViewModel { ReturnUrl = SafeReturnUrl(returnUrl) });
            }
        }
        return await ChallengeViewAsync(user.Id, returnUrl);
    }

    [HttpPost("totp")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertTotp(
        LoginMfaChallengeTotpRequest request, CancellationToken cancellationToken)
    {
        var user = await ResolveChallengeUserAsync(cancellationToken);
        if (user is null)
        {
            return Redirect("/account/login");
        }
        if (!ModelState.IsValid || string.IsNullOrWhiteSpace(request.Code))
        {
            return await ChallengeViewAsync(user.Id, request.ReturnUrl, "请输入验证码。");
        }
        if (!TryAcquireRateLimit(user.Id, out var error))
        {
            return await ChallengeViewAsync(user.Id, request.ReturnUrl, error);
        }
        if (!await mfa.VerifyAsync(user.Id, request.Code.Trim(), cancellationToken))
        {
            await RecordSecurityEventAsync("login.mfa_challenge_failed", user.Id, MfaClaimTypes.Totp, cancellationToken);
            return await ChallengeViewAsync(user.Id, request.ReturnUrl, "验证码错误、已过期或已被使用。");
        }
        await CompleteChallengeAsync(user, MfaClaimTypes.Totp, cancellationToken);
        return LocalRedirect(SafeReturnUrl(request.ReturnUrl));
    }

    /// <summary>恢复码挑战：单次消费，成功即签入（amr=recovery_code）；Passkey 退役后的存量账号自救通道。</summary>
    [HttpPost("recovery")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertRecoveryCode(
        LoginMfaChallengeRecoveryRequest request, CancellationToken cancellationToken)
    {
        var user = await ResolveChallengeUserAsync(cancellationToken);
        if (user is null)
        {
            return Redirect("/account/login");
        }
        if (!ModelState.IsValid || string.IsNullOrWhiteSpace(request.Code))
        {
            return await ChallengeViewAsync(user.Id, request.ReturnUrl, "请输入恢复码。");
        }
        if (!TryAcquireRateLimit(user.Id, out var error))
        {
            return await ChallengeViewAsync(user.Id, request.ReturnUrl, error);
        }
        if (!await mfa.ConsumeRecoveryCodeAsync(user.Id, request.Code.Trim(), cancellationToken))
        {
            await RecordSecurityEventAsync("login.mfa_challenge_failed", user.Id, MfaClaimTypes.RecoveryCode, cancellationToken);
            return await ChallengeViewAsync(user.Id, request.ReturnUrl, "恢复码无效或已使用。");
        }
        await CompleteChallengeAsync(user, MfaClaimTypes.RecoveryCode, cancellationToken);
        return LocalRedirect(SafeReturnUrl(request.ReturnUrl));
    }

    /// <summary>从 pending 挑战 cookie 解析用户：cookie 无效/过期、用户不存在、非活跃或安全戳已变都视为挑战失效。</summary>
    private async Task<PandaUser?> ResolveChallengeUserAsync(CancellationToken cancellationToken)
    {
        var challenge = challenges.Read(HttpContext);
        if (challenge is null)
        {
            challenges.Clear(HttpContext);
            return null;
        }
        var user = await users.FindByIdAsync(challenge.UserId);
        if (user is null || user.Status != UserStatus.Active ||
            string.IsNullOrEmpty(user.SecurityStamp) || user.SecurityStamp != challenge.SecurityStamp)
        {
            challenges.Clear(HttpContext);
            return null;
        }
        return user;
    }

    private async Task<bool> HasRecoveryCodesAsync(string userId, CancellationToken cancellationToken)
        => await mfa.HasRecoveryCodesAsync(userId, cancellationToken);

    private bool TryAcquireRateLimit(string userId, out string error)
    {
        using var ipLease = loginRateLimiter.AttemptMfaChallengeByIp(
            HttpContext.Connection.RemoteIpAddress?.ToString());
        using var userLease = loginRateLimiter.AttemptMfaChallengeByUser(userId);
        if (ipLease.IsAcquired && userLease.IsAcquired)
        {
            error = string.Empty;
            return true;
        }
        error = "尝试过于频繁，请稍后再试。";
        return false;
    }

    private async Task CompleteChallengeAsync(PandaUser user, string method, CancellationToken cancellationToken)
    {
        await sessions.SignInWithMfaAsync(HttpContext, user, method);
        challenges.Clear(HttpContext);
        await RecordSecurityEventAsync("login.mfa_challenge_succeeded", user.Id, method, cancellationToken);
    }

    /// <summary>断言失败后重绘挑战页；因子可用性按当前实际状态重查，避免把不存在的因子入口展示给用户。</summary>
    private async Task<IActionResult> ChallengeViewAsync(string userId, string? returnUrl, string? message = null)
    {
        var factors = await mfa.ListFactorsAsync(userId, CancellationToken.None);
        if (message is not null) ModelState.AddModelError(string.Empty, message);
        return View("Index", new LoginMfaChallengeViewModel
        {
            ReturnUrl = SafeReturnUrl(returnUrl),
            HasTotp = factors.Any(factor => factor.Type == "totp"),
            HasRecoveryCodes = await HasRecoveryCodesAsync(userId, CancellationToken.None),
        });
    }

    private string SafeReturnUrl(string? returnUrl) => Url.IsLocalUrl(returnUrl) ? returnUrl! : "/me/";

    private Task RecordSecurityEventAsync(
        string eventType, string userId, string authenticationMethod, CancellationToken cancellationToken)
        => securityEvents is null
            ? Task.CompletedTask
            : securityEvents.RecordAsync(new SecurityEventEntry(
                eventType,
                userId,
                userId,
                "user",
                userId,
                authenticationMethod,
                null,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString(),
                HttpContext.TraceIdentifier), cancellationToken);
}
