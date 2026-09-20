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
    LoginSessionService sessions,
    PandaAuthDbContext db,
    ILogger<MfaController> logger) : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        var count = await db.WebAuthnCredentials.CountAsync(item => item.UserId == user.Id && item.RevokedAt == null, cancellationToken);
        return View(new MfaViewModel { ActivePasskeyCount = count });
    }

    [HttpPost("enrollment/options")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnrollmentOptions(CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        var ceremony = await ceremonies.BeginEnrollmentAsync(user, cancellationToken);
        return Json(new { ceremonyId = ceremony.Id, publicKey = ceremony.Options });
    }

    [HttpPost("enrollment/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteEnrollment([FromBody] CompletePasskeyEnrollmentRequest request, CancellationToken cancellationToken)
    {
        var user = await AdminAsync();
        if (user is null) return Forbid();
        if (request.Response is null) return BadRequest(new { error = "缺少 Passkey 响应。" });
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

    private async Task<PandaUser?> AdminAsync()
    {
        var user = await users.GetUserAsync(User);
        return user is not null && (await users.GetRolesAsync(user)).Contains(PandaUser.AdminRole, StringComparer.OrdinalIgnoreCase)
            ? user : null;
    }
}
