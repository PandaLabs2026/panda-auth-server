using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Admin;

public sealed record AdminGrantRequest
{
    public string Operation { get; init; } = string.Empty;
    public string TargetId { get; init; } = string.Empty;
    public Dictionary<string, string?>? Parameters { get; init; }
    public string TotpCode { get; init; } = string.Empty;
    public string? CurrentPassword { get; init; }
}

/// <summary>
/// 管理域操作授权签发（AUTH-DELIVERY-002）：高风险/特敏感管理操作的单次 TOTP 授权入口。
/// 操作者身份取自 Bearer 令牌 subject，绝不接受请求体指定；签发校验 TOTP（防重放）
/// 与特敏感操作的操作者本人密码，消费在各受保护端点完成（MfaOperationGrantGate）。
/// </summary>
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
    Policy = AdminApiAuthorization.PolicyName)]
[Route("~/admin-api/mfa-grants")]
public sealed class AdminMfaGrantsController(
    MfaOperationGrantService grants,
    LoginRateLimiter loginRateLimiter,
    SecurityEventWriter? securityEvents = null) : Controller
{
    [HttpPost]
    public async Task<IActionResult> Issue([FromBody] AdminGrantRequest? request, CancellationToken cancellationToken)
    {
        var subject = User.FindFirst(Claims.Subject)?.Value;
        if (string.IsNullOrEmpty(subject)) return Forbid();
        if (request is null || string.IsNullOrWhiteSpace(request.Operation))
        {
            return BadRequest(new { error = "请求体缺失。" });
        }

        // 与 step-up 断言同策略：六位码可脚本化重试，须先于业务校验拒绝（IP+操作者双维）。
        using var ipLease = loginRateLimiter.AttemptMfaChallengeByIp(
            HttpContext.Connection.RemoteIpAddress?.ToString());
        using var userLease = loginRateLimiter.AttemptMfaChallengeByUser(subject);
        if (!ipLease.IsAcquired || !userLease.IsAcquired)
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { error = "尝试过于频繁，请稍后再试。" });
        }

        var (issued, error) = await grants.IssueAsync(
            subject, request.Operation, request.TargetId, request.Parameters,
            request.TotpCode, request.CurrentPassword, cancellationToken);
        if (issued is null) return MfaOperationGrantGate.IssueError(error);

        if (securityEvents is not null)
        {
            await securityEvents.RecordAsync(new SecurityEventEntry(
                "mfa.grant_issued",
                subject,
                subject,
                "mfa_grant",
                request.TargetId,
                MfaClaimTypes.Totp,
                new { operation = request.Operation, targetId = request.TargetId },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString(),
                HttpContext.TraceIdentifier), cancellationToken);
        }
        return Ok(new { grantId = issued.GrantId, expiresAt = issued.ExpiresAt });
    }
}
