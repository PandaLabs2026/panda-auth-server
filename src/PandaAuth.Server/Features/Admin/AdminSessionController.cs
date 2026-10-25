using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 管理域会话探针：与 admin-api 主策略同一身份口径（HasResource），但不设 TOTP 绑定门——
/// 未绑定 TOTP 的管理员正是靠它拿到 { totpEnrollmentRequired } 信号并进入绑定引导，
/// 其余全部 admin-api 端点对该类身份一律拒绝（AdminResourceHandler）。
/// </summary>
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
    Policy = AdminApiAuthorization.SessionPolicyName)]
[Route("~/admin-api/session")]
public sealed class AdminSessionController(PandaAuthDbContext db) : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasResource(User)) return Forbid();
        var subject = User.FindFirst(Claims.Subject)?.Value;
        if (string.IsNullOrEmpty(subject)) return Forbid();

        var totpBound = await db.TotpFactors.AnyAsync(
            factor => factor.UserId == subject && factor.RevokedAt == null && factor.ConfirmedAt != null,
            cancellationToken);
        return Ok(new
        {
            totpBound,
            // 当前令牌是否已满足普通写操作的 8 小时 amr 窗（供 SPA 预判 step-up 状态）。
            mfaSatisfied = AdminApiAuthorization.HasValidMfa(User),
        });
    }
}
