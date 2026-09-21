using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;

namespace PandaAuth.Server.Features.Account;

/// <summary>管理员 Passkey ceremony 入口。用户身份仅取自已验证的 IDP cookie，绝不接受请求体指定 subject。</summary>
[Authorize]
[Route("~/account/mfa")]
public sealed class MfaController(
    UserService users,
    WebAuthnCeremonyService ceremonies,
    TotpFactorService totpFactors,
    LoginSessionService sessions,
    PandaAuthDbContext db,
    ILogger<MfaController> logger,
    MfaService? mfa = null) : Controller
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
            var enrollment = await totpFactors.BeginEnrollmentAsync(user.Id, cancellationToken, requirePasskey: false);
            return Ok(new { factorId = enrollment.FactorId, secret = enrollment.Secret, provisioningUri = enrollment.ProvisioningUri });
        }
        catch (InvalidOperationException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [AllowAnonymous]
    [HttpPost("user/reconfigure/totp/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmLegacyTotpReconfiguration(
        [FromBody] ConfirmTotpRequest request, CancellationToken cancellationToken)
    {
        var user = await sessions.GetReconfigurationUserAsync(HttpContext);
        if (user is null || mfa is null) return Forbid();
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

    [HttpPost("user/recovery-codes")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> GenerateUserRecoveryCodes(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        try
        {
            var codes = await mfa.GenerateRecoveryCodesAsync(user.Id, User, cancellationToken);
            return Json(codes);
        }
        catch (MfaPolicyException) { return Forbid(); }
    }

    [HttpPost("user/passkey/enrollment/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginUserPasskeyEnrollment(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        try
        {
            await mfa.RequireEnrollmentAsync(user.Id, User, cancellationToken);
            var ceremony = await ceremonies.BeginEnrollmentAsync(user, cancellationToken);
            return Json(new { ceremonyId = ceremony.Id, publicKey = ceremony.Options });
        }
        catch (MfaPolicyException) { return Forbid(); }
    }

    [HttpPost("user/passkey/enrollment/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteUserPasskeyEnrollment(
        [FromBody] CompletePasskeyEnrollmentRequest? request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (request is null || request.Response is null) return BadRequest(new { error = "缺少 Passkey 响应。" });
        try
        {
            await mfa.RequireEnrollmentAsync(user.Id, User, cancellationToken);
            await ceremonies.CompleteEnrollmentAsync(user, request.CeremonyId, request.Response, request.FriendlyName, cancellationToken);
            var count = await db.WebAuthnCredentials.CountAsync(item => item.UserId == user.Id && item.RevokedAt == null, cancellationToken);
            return Ok(new { status = "ok", activePasskeyCount = count });
        }
        catch (MfaPolicyException) { return Forbid(); }
        catch (Exception exception) when (exception is InvalidOperationException or Fido2NetLib.Fido2VerificationException)
        {
            return BadRequest(new { error = "Passkey 注册未完成，请重试。" });
        }
    }

    [HttpPost("user/passkey/assertion/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginUserPasskeyAssertion(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null) return Forbid();
        try
        {
            var ceremony = await ceremonies.BeginAssertionAsync(user, cancellationToken);
            return Json(new { ceremonyId = ceremony.Id, publicKey = ceremony.Options });
        }
        catch (InvalidOperationException) { return BadRequest(new { error = "此账号尚未配置可用的 Passkey。" }); }
    }

    [HttpPost("user/passkey/assertion/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteUserPasskeyAssertion(
        [FromBody] CompletePasskeyAssertionRequest? request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null) return Forbid();
        if (request is null || request.Response is null) return BadRequest(new { error = "缺少 Passkey 响应。" });
        try
        {
            await ceremonies.CompleteAssertionAsync(user, request.CeremonyId, request.Response, cancellationToken);
            await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.WebAuthn);
            return Ok(new { status = "ok" });
        }
        catch (Exception exception) when (exception is InvalidOperationException or Fido2NetLib.Fido2VerificationException)
        {
            return BadRequest(new { error = "Passkey 验证未完成，请重试。" });
        }
    }

    [HttpPost("user/totp/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginUserTotp(CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        try
        {
            var enrollment = await mfa.BeginEnrollmentAsync(user.Id, User, MfaFactorType.Totp, cancellationToken);
            return Ok(new { factorId = enrollment.FactorId, secret = enrollment.Secret, provisioningUri = enrollment.ProvisioningUri });
        }
        catch (MfaPolicyException) { return Forbid(); }
        catch (InvalidOperationException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [HttpPost("user/totp/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmUserTotp([FromBody] ConfirmTotpRequest request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (!await mfa.ConfirmEnrollmentAsync(user.Id, User, request.FactorId, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误或已过期。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        return Ok(new { status = "ok" });
    }

    [HttpPost("user/totp/assert")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertUserTotp([FromBody] ConfirmTotpRequest request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (!await mfa.VerifyAsync(user.Id, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误、已过期或已被使用。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        return Ok(new { status = "ok" });
    }

    [HttpPost("user/factors/revoke")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeUserFactor([FromBody] RevokeMfaFactorRequest request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        try
        {
            await mfa.RevokeFactorAsync(user.Id, request.FactorId, User, cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (MfaPolicyException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [HttpPost("user/recovery-codes/consume")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConsumeUserRecoveryCode([FromBody] ConsumeRecoveryCodeRequest request, CancellationToken cancellationToken)
    {
        var user = await CurrentAsync();
        if (user is null || mfa is null) return Forbid();
        if (!await mfa.ConsumeRecoveryCodeAsync(user.Id, request.Code, cancellationToken))
            return BadRequest(new { error = "恢复码无效或已使用。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.RecoveryCode);
        return Ok(new { status = "ok" });
    }

    [HttpGet]
    public async Task<IActionResult> Index(string? returnUrl, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        var count = await db.WebAuthnCredentials.CountAsync(item => item.UserId == user.Id && item.RevokedAt == null, cancellationToken);
        var hasTotp = await db.TotpFactors.AnyAsync(item => item.UserId == user.Id && item.RevokedAt == null && item.ConfirmedAt != null, cancellationToken);
        return View(new MfaViewModel { ActivePasskeyCount = count, HasTotp = hasTotp, ReturnUrl = Url.IsLocalUrl(returnUrl) ? returnUrl! : "/admin/" });
    }

    [HttpPost("enrollment/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnrollmentOptions(CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (!user.EmailConfirmed) return Forbid();
        var ceremony = await ceremonies.BeginEnrollmentAsync(user, cancellationToken);
        return Json(new { ceremonyId = ceremony.Id, publicKey = ceremony.Options });
    }

    [HttpPost("enrollment/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteEnrollment([FromBody] CompletePasskeyEnrollmentRequest? request, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (!user.EmailConfirmed) return Forbid();
        if (request is null || request.Response is null) return BadRequest(new { error = "缺少 Passkey 响应。" });
        try
        {
            await ceremonies.CompleteEnrollmentAsync(user, request.CeremonyId, request.Response, request.FriendlyName, cancellationToken);
            logger.LogInformation("Passkey registered adminId={UserId}", user.Id);
            return Ok(new { status = "ok" });
        }
        catch (Exception exception) when (exception is InvalidOperationException or Fido2NetLib.Fido2VerificationException)
        {
            logger.LogWarning(exception, "Passkey enrollment rejected adminId={UserId}", user.Id);
            return BadRequest(new { error = "Passkey 注册未完成，请重试。" });
        }
    }

    [HttpPost("assertion/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertionOptions(CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        try
        {
            var ceremony = await ceremonies.BeginAssertionAsync(user, cancellationToken);
            return Json(new { ceremonyId = ceremony.Id, publicKey = ceremony.Options });
        }
        catch (InvalidOperationException) { return BadRequest(new { error = "此账号尚未配置可用的 Passkey。" }); }
    }

    [HttpPost("assertion/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteAssertion([FromBody] CompletePasskeyAssertionRequest request, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (request.Response is null) return BadRequest(new { error = "缺少 Passkey 响应。" });
        try
        {
            await ceremonies.CompleteAssertionAsync(user, request.CeremonyId, request.Response, cancellationToken);
            await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.WebAuthn);
            logger.LogInformation("Passkey assertion succeeded adminId={UserId}", user.Id);
            return Ok(new { status = "ok" });
        }
        catch (Exception exception) when (exception is InvalidOperationException or Fido2NetLib.Fido2VerificationException)
        {
            logger.LogWarning(exception, "Passkey assertion rejected adminId={UserId}", user.Id);
            return BadRequest(new { error = "Passkey 验证未完成，请重试。" });
        }
    }

    [HttpPost("totp/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BeginTotp(CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (!user.EmailConfirmed) return Forbid();
        try
        {
            var enrollment = await totpFactors.BeginEnrollmentAsync(user.Id, cancellationToken);
            return Ok(new { factorId = enrollment.FactorId, secret = enrollment.Secret, provisioningUri = enrollment.ProvisioningUri });
        }
        catch (InvalidOperationException exception) { return BadRequest(new { error = exception.Message }); }
    }

    [HttpPost("totp/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmTotp([FromBody] ConfirmTotpRequest request, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (!user.EmailConfirmed) return Forbid();
        if (!await totpFactors.ConfirmAsync(user.Id, request.FactorId, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误或已过期。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        logger.LogInformation("TOTP confirmed adminId={UserId}", user.Id);
        return Ok(new { status = "ok" });
    }

    [HttpPost("totp/assert")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertTotp([FromBody] ConfirmTotpRequest request, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (!await totpFactors.VerifyAsync(user.Id, request.Code, cancellationToken))
            return BadRequest(new { error = "验证码错误、已过期或已被使用。" });
        await sessions.MarkMfaAsync(HttpContext, MfaClaimTypes.Totp);
        logger.LogInformation("TOTP assertion succeeded adminId={UserId}", user.Id);
        return Ok(new { status = "ok" });
    }

    private async Task<PandaUser?> AdminAsync()
    {
        var user = await users.GetUserAsync(User);
        return user is not null && (await users.GetRolesAsync(user)).Contains(PandaUser.AdminRole, StringComparer.OrdinalIgnoreCase)
            ? user : null;
    }

    private Task<PandaUser?> CurrentAsync() => users.GetUserAsync(User);
}
