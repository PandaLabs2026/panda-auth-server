using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;

namespace PandaAuth.Server.Features.Account;

/// <summary>
/// MFA 自助面（管理员安全验证页 + me 安全设置的 /account/mfa/user/* 数据端）。
/// Passkey 已退役（AUTH-DELIVERY-002）：本控制器只承载 TOTP、恢复码与操作授权；
/// 特敏感自助操作（换绑 TOTP/撤销 TOTP/重生成恢复码）经 user/grants 签发单次操作授权，
/// 授权验证 = TOTP 码 + 操作者本人密码。退役 passkey 存量行的撤销是迁移动作，走首因子解锁口径。
/// </summary>
[Authorize]
[Route("~/account/mfa")]
public sealed class MfaController(
    UserService users,
    TotpFactorService totpFactors,
    LoginSessionService sessions,
    PandaAuthDbContext db,
    MfaOperationGrantService grants,
    ILogger<MfaController> logger,
    LoginRateLimiter loginRateLimiter,
    MfaService? mfa = null,
    SecurityEventWriter? securityEvents = null) : Controller
{
    [AllowAnonymous]
    [HttpGet("user/reconfigure")]
    public async Task<IActionResult> LegacyReconfigurationStatus(CancellationToken cancellationToken)
    {
        var user = await sessions.GetReconfigurationUserAsync(HttpContext);
        if (user is null || mfa is null) return Forbid();
        return Json(await mfa.GetStatusAsync(user.Id, cancellationToken));
    }

    [AllowAnonymous]
    [HttpPost("user/reconfigure/totp/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginLegacyTotpReconfiguration(CancellationToken cancellationToken)
    {
        var user = await sessions.GetReconfigurationUserAsync(HttpContext);
        if (user is null) return Forbid();
        if (!user.EmailConfirmed) return Forbid();
        try
        {
            var enrollment = await totpFactors.BeginEnrollmentAsync(user.Id, cancellationToken);
            return Ok(new { factorId = enrollment.FactorId, secret = enrollment.Secret, provisioningUri = enrollment.ProvisioningUri });
        }
        catch (InvalidOperationException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [AllowAnonymous]
    [HttpPost("user/reconfigure/totp/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmLegacyTotpReconfiguration(
        [FromBody] ConfirmTotpRequest? request, CancellationToken cancellationToken)
    {
        var user = await sessions.GetReconfigurationUserAsync(HttpContext);
        if (user is null || mfa is null) return Forbid();
        // 空 body 直接 400，而不是解引用跌成 500（既有口径）。
        if (request is null) return BadRequest(new { error = "请求体缺失。" });
        try
        {
            if (!await mfa.ConfirmLegacyReconfigurationAsync(user.Id, request.FactorId, request.Code, cancellationToken))
                return BadRequest(new { error = "验证码错误或已过期。" });
            await sessions.SignOutReconfigurationAsync(HttpContext);
            return Ok(new { status = "ok", reauthenticationRequired = true });
        }
        catch (MfaPolicyException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [HttpGet("user/status")]
    public async Task<IActionResult> UserStatus(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        return Json(await mfa.GetStatusAsync(user.Id, cancellationToken));
    }

    [HttpGet("user/factors")]
    public async Task<IActionResult> UserFactors(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        return Json(await mfa.ListFactorsAsync(user.Id, cancellationToken));
    }

    /// <summary>给同源 SPA 发放 antiforgery 请求令牌（IDP 未配置自定义 header，前端用默认 RequestVerificationToken 头回传）。</summary>
    [HttpGet("user/antiforgery")]
    public IActionResult UserAntiforgeryToken([FromServices] IAntiforgery antiforgery)
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return Ok(new { token = tokens.RequestToken });
    }

    /// <summary>
    /// 用户自助域操作授权签发：特敏感自助操作（换绑 TOTP/撤销 TOTP/重生成恢复码）的单次授权。
    /// TOTP 验证成功同时把 MFA 事实标记到 IDP cookie——同批后续服务端策略检查
    /// （首因子解锁/近期认证）以同一验证事实通过，不要求二次输入。
    /// </summary>
    [HttpPost("user/grants")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> IssueUserGrant([FromBody] UserGrantRequest? request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (request is null || string.IsNullOrWhiteSpace(request.Operation)) return BadRequest(new { error = "请求体缺失。" });
        if (RateGate(user.Id) is { } limited) return limited;

        var (issued, error) = await grants.IssueAsync(
            user.Id, request.Operation, request.TargetId, request.Parameters,
            request.TotpCode, request.CurrentPassword, cancellationToken);
        if (issued is null) return MfaOperationGrantGate.IssueError(error);

        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        await RecordSecurityEventAsync("mfa.grant_issued", user.Id, MfaClaimTypes.Totp,
            new { operation = request.Operation, targetId = request.TargetId }, cancellationToken);
        return Ok(new { grantId = issued.GrantId, expiresAt = issued.ExpiresAt });
    }

    /// <summary>
    /// 恢复码重生成（特敏感：旧码整体作废换新码）。已绑定 TOTP 时须持 self.recovery-codes
    /// 操作授权；无可验证因子（迁移期）沿用服务端首因子解锁策略。
    /// </summary>
    [HttpPost("user/recovery-codes")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> GenerateUserRecoveryCodes(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (await mfa.HasVerifiableFactorAsync(user.Id, cancellationToken))
        {
            if (await MfaOperationGrantGate.ConsumeAsync(this, grants, securityEvents, user.Id,
                    MfaOperations.SelfRecoveryCodes, user.Id, null, cancellationToken) is { } denied)
            {
                return denied;
            }
        }
        try
        {
            var codes = await mfa.GenerateRecoveryCodesAsync(user.Id, User, cancellationToken);
            return Json(codes);
        }
        catch (MfaPolicyException) { return Forbid(); }
    }

    [HttpPost("user/totp/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginUserTotp(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        // 换绑（已有 TOTP）须持 self.totp-enroll 操作授权（TOTP+密码验证）；
        // 首次绑定无可验证因子，沿用首因子解锁（5 分钟内密码登录）。
        if (await mfa.HasVerifiableFactorAsync(user.Id, cancellationToken))
        {
            if (await MfaOperationGrantGate.ConsumeAsync(this, grants, securityEvents, user.Id,
                    MfaOperations.SelfTotpEnroll, user.Id, null, cancellationToken) is { } denied)
            {
                return denied;
            }
        }
        try
        {
            var enrollment = await mfa.BeginEnrollmentAsync(user.Id, User, cancellationToken);
            return Ok(new { factorId = enrollment.FactorId, secret = enrollment.Secret, provisioningUri = enrollment.ProvisioningUri });
        }
        catch (MfaPolicyException) { return Forbid(); }
        catch (InvalidOperationException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [HttpPost("user/totp/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmUserTotp([FromBody] ConfirmTotpRequest? request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (request is null) return BadRequest(new { error = "请求体缺失。" });
        if (!await mfa.ConfirmEnrollmentAsync(user.Id, User, request.FactorId, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误或已过期。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        await RecordSecurityEventAsync("user.totp_enrolled", user.Id, MfaClaimTypes.Totp, null, cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("user/totp/assert")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertUserTotp([FromBody] ConfirmTotpRequest? request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (request is null) return BadRequest(new { error = "请求体缺失。" });
        // step-up 断言限流（IP+用户双维，与登录 MFA 挑战同策略）：六位码可暴力尝试，
        // 会话劫持下必须先于校验拒绝；与登录挑战共用同一限流器与窗口配额。
        if (RateGate(user.Id) is { } limited) return limited;
        if (!await mfa.VerifyAsync(user.Id, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误、已过期或已被使用。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        await RecordSecurityEventAsync("user.totp_asserted", user.Id, MfaClaimTypes.Totp, null, cancellationToken);
        return Ok(new { status = "ok" });
    }

    /// <summary>
    /// 因子撤销分级：撤销 TOTP（特敏感，撤掉即失去可验证因子）须持 self.revoke-factor
    /// 操作授权；撤销退役 passkey 存量行是迁移动作，走服务端既有策略（首因子解锁/近期认证）。
    /// </summary>
    [HttpPost("user/factors/revoke")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeUserFactor([FromBody] RevokeMfaFactorRequest? request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (request is null) return BadRequest(new { error = "请求体缺失。" });
        var isTotp = await db.TotpFactors.AnyAsync(
            x => x.Id == request.FactorId && x.UserId == user.Id && x.RevokedAt == null && x.ConfirmedAt != null,
            cancellationToken);
        if (isTotp)
        {
            if (await MfaOperationGrantGate.ConsumeAsync(this, grants, securityEvents, user.Id,
                    MfaOperations.SelfRevokeFactor, request.FactorId.ToString(),
                    new Dictionary<string, string?> { ["factorType"] = "totp" }, cancellationToken) is { } denied)
            {
                return denied;
            }
        }
        try
        {
            await mfa.RevokeFactorAsync(user.Id, request.FactorId, User, cancellationToken);
            await RecordSecurityEventAsync("user.mfa_factor_revoked", user.Id, null, new { factorId = request.FactorId }, cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (MfaPolicyException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [HttpPost("user/recovery-codes/consume")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConsumeUserRecoveryCode([FromBody] ConsumeRecoveryCodeRequest? request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (request is null) return BadRequest(new { error = "请求体缺失。" });
        if (!await mfa.ConsumeRecoveryCodeAsync(user.Id, request.Code, cancellationToken))
            return BadRequest(new { error = "恢复码无效或已使用。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.RecoveryCode);
        await RecordSecurityEventAsync("user.recovery_code_used", user.Id, MfaClaimTypes.RecoveryCode, null, cancellationToken);
        return Ok(new { status = "ok" });
    }

    /// <summary>
    /// 管理员安全验证页（/account/mfa）：Passkey 退役后为 TOTP-first——
    /// 首次绑定（无 TOTP）提供配置入口；已绑定时只提供 step-up 验证（amr 刷新），
    /// 换绑/撤销引导到 me 账户中心安全设置（走操作授权+密码）。
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Index(string? returnUrl, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        var hasTotp = await db.TotpFactors.AnyAsync(item => item.UserId == user.Id && item.RevokedAt == null && item.ConfirmedAt != null, cancellationToken);
        return View(new MfaViewModel { HasTotp = hasTotp, ReturnUrl = Url.IsLocalUrl(returnUrl) ? returnUrl! : "/admin/" });
    }

    [HttpPost("totp/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginTotp(CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (!user.EmailConfirmed) return Forbid();
        if (await db.TotpFactors.AnyAsync(item => item.UserId == user.Id && item.RevokedAt == null && item.ConfirmedAt != null, cancellationToken))
        {
            // 已绑定者在本页只做 step-up 验证；换绑走 me 安全设置的授权流程（TOTP+密码）。
            return BadRequest(new { error = "已配置 TOTP。如需更换，请前往账户中心安全设置。" });
        }
        if (await RequireAdminEnrollmentAsync(user, cancellationToken) is { } restricted) return restricted;
        try
        {
            var enrollment = await totpFactors.BeginEnrollmentAsync(user.Id, cancellationToken);
            return Ok(new { factorId = enrollment.FactorId, secret = enrollment.Secret, provisioningUri = enrollment.ProvisioningUri });
        }
        catch (InvalidOperationException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [HttpPost("totp/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmTotp([FromBody] ConfirmTotpRequest? request, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (!user.EmailConfirmed) return Forbid();
        if (request is null) return BadRequest(new { error = "请求体缺失。" });
        if (await RequireAdminEnrollmentAsync(user, cancellationToken) is { } restricted) return restricted;
        if (RateGate(user.Id) is { } limited) return limited;
        if (!await totpFactors.ConfirmAsync(user.Id, request.FactorId, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误或已过期。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        await RecordSecurityEventAsync("admin.totp_enrolled", user.Id, MfaClaimTypes.Totp, null, cancellationToken);
        logger.LogInformation("TOTP confirmed adminId={UserId}", user.Id);
        return Ok(new { status = "ok" });
    }

    [HttpPost("totp/assert")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertTotp([FromBody] ConfirmTotpRequest? request, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (request is null) return BadRequest(new { error = "请求体缺失。" });
        if (RateGate(user.Id) is { } limited) return limited;
        if (!await totpFactors.VerifyAsync(user.Id, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误、已过期或已被使用。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        await RecordSecurityEventAsync("admin.totp_asserted", user.Id, MfaClaimTypes.Totp, null, cancellationToken);
        logger.LogInformation("TOTP assertion succeeded adminId={UserId}", user.Id);
        return Ok(new { status = "ok" });
    }

    private async Task<PandaUser?> AdminAsync()
    {
        var user = await users.GetUserAsync(User);
        return user is not null && (await users.GetRolesAsync(user)).Contains(PandaUser.AdminRole, StringComparer.OrdinalIgnoreCase)
            ? user : null;
    }

    /// <summary>
    /// 管理员因子注册/确认的再认证门：与用户路径共用 MfaService 的近期认证策略。
    /// 会话劫持者即使拿到管理员 Cookie，也不能直接把自己的 TOTP 绑定到受害者账号。
    /// </summary>
    private async Task<IActionResult?> RequireAdminEnrollmentAsync(PandaUser user, CancellationToken cancellationToken)
    {
        if (mfa is null) return Forbid();
        try
        {
            await mfa.RequireEnrollmentAsync(user.Id, User, cancellationToken);
            return null;
        }
        catch (MfaPolicyException)
        {
            return Forbid();
        }
    }

    /// <summary>
    /// step-up 断言限流门（IP+用户双维，与 LoginMfaChallengeController 同一限流器与配额）：
    /// 通过返回 null，被拒返回 429 + 文案。TOTP 六位码可脚本化重试，
    /// 会话劫持场景必须先于业务校验拒绝。
    /// </summary>
    private IActionResult? RateGate(string userId)
    {
        using var ipLease = loginRateLimiter.AttemptMfaChallengeByIp(
            HttpContext.Connection.RemoteIpAddress?.ToString());
        using var userLease = loginRateLimiter.AttemptMfaChallengeByUser(userId);
        return ipLease.IsAcquired && userLease.IsAcquired
            ? null
            : StatusCode(StatusCodes.Status429TooManyRequests, new { error = "尝试过于频繁，请稍后再试。" });
    }

    private Task<PandaUser?> CurrentAsync() => users.GetUserAsync(User);

    private Task RecordSecurityEventAsync(
        string eventType,
        string userId,
        string? authenticationMethod,
        object? metadata,
        CancellationToken cancellationToken)
        => securityEvents is null
            ? Task.CompletedTask
            : securityEvents.RecordAsync(new SecurityEventEntry(
                eventType,
                userId,
                User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
                "user",
                userId,
                authenticationMethod,
                metadata,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString(),
                HttpContext.TraceIdentifier), cancellationToken);
}
