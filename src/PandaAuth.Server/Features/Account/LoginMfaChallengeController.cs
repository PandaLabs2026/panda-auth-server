using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Account;

/// <summary>
/// 登录路径 MFA 挑战入口（2026-09-30 拍板）。用户身份只取自 pending 挑战 cookie——
/// 它在密码验证通过后、有任何活跃因子时签发，且绑定签发时的安全戳；绝不接受请求体指定 subject。
/// 断言成功才签发携带 amr/panda_mfa_at 的 IDP 登录 cookie（SignInWithMfaAsync）。
/// </summary>
[AllowAnonymous]
[Route("~/account/mfa/challenge")]
public sealed class LoginMfaChallengeController(
    UserService users,
    MfaService mfa,
    WebAuthnCeremonyService ceremonies,
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
        if (factors.Count == 0)
        {
            // 签发挑战后因子被全部撤销：无法完成挑战，回登录页重新走密码路径（无因子即不再要求挑战）。
            challenges.Clear(HttpContext);
            return Redirect("/account/login");
        }
        return View(new LoginMfaChallengeViewModel
        {
            ReturnUrl = Url.IsLocalUrl(returnUrl) ? returnUrl! : "/",
            HasTotp = factors.Any(factor => factor.Type == "totp"),
            HasPasskey = factors.Any(factor => factor.Type == "passkey"),
        });
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

    [HttpPost("passkey/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginPasskeyAssertion(CancellationToken cancellationToken)
    {
        var user = await ResolveChallengeUserAsync(cancellationToken);
        if (user is null)
        {
            return BadRequest(new { error = "验证会话已过期，请重新登录。" });
        }
        try
        {
            var ceremony = await ceremonies.BeginAssertionAsync(user, cancellationToken);
            return Json(new { ceremonyId = ceremony.Id, publicKey = ceremony.Options });
        }
        catch (InvalidOperationException)
        {
            return BadRequest(new { error = "此账号尚未配置可用的 Passkey。" });
        }
    }

    [HttpPost("passkey/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompletePasskeyAssertion(
        [FromBody] CompletePasskeyAssertionRequest? request, CancellationToken cancellationToken)
    {
        var user = await ResolveChallengeUserAsync(cancellationToken);
        if (user is null)
        {
            return BadRequest(new { error = "验证会话已过期，请重新登录。" });
        }
        if (request is null || request.Response is null)
        {
            return BadRequest(new { error = "缺少 Passkey 响应。" });
        }
        if (!TryAcquireRateLimit(user.Id, out var error))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { error });
        }
        try
        {
            await ceremonies.CompleteAssertionAsync(user, request.CeremonyId, request.Response, cancellationToken);
        }
        catch (Exception exception) when (exception is InvalidOperationException or Fido2NetLib.Fido2VerificationException)
        {
            await RecordSecurityEventAsync("login.mfa_challenge_failed", user.Id, MfaClaimTypes.WebAuthn, cancellationToken);
            return BadRequest(new { error = "Passkey 验证未完成，请重试。" });
        }
        await CompleteChallengeAsync(user, MfaClaimTypes.WebAuthn, cancellationToken);
        return Ok(new { status = "ok" });
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
    private async Task<IActionResult> ChallengeViewAsync(string userId, string? returnUrl, string message)
    {
        var factors = await mfa.ListFactorsAsync(userId, CancellationToken.None);
        ModelState.AddModelError(string.Empty, message);
        return View("Index", new LoginMfaChallengeViewModel
        {
            ReturnUrl = SafeReturnUrl(returnUrl),
            HasTotp = factors.Any(factor => factor.Type == "totp"),
            HasPasskey = factors.Any(factor => factor.Type == "passkey"),
        });
    }

    private string SafeReturnUrl(string? returnUrl) => Url.IsLocalUrl(returnUrl) ? returnUrl! : "/";

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
