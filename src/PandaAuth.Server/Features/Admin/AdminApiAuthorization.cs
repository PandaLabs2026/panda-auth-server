using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Admin;

/// <summary>Admin 数据 API 的授权约定（策略名），控制器特性与 Program.cs 注册处共用。</summary>
internal static class AdminApiAuthorization
{
    public static bool HasResource(ClaimsPrincipal principal)
        => principal.Identity?.IsAuthenticated == true
           && principal.GetClaim(PandaAuthClaims.SubjectType) == PandaAuthClaims.SubjectTypes.Human
           && principal.HasAudience(PandaAuthAdminApi.Audience)
           && principal.HasScope(PandaAuthAdminApi.Scope)
           && principal.GetPresenters() is { Length: 1 } presenters
           && presenters[0] == PandaAuthAdminApi.ClientId
           && principal.HasClaim(OpenIddictConstants.Claims.Role, PandaAuthRoles.Admin);

    /// <summary>API step-up rejection must not invoke the host's default cookie forbid redirect.</summary>
    public static Microsoft.AspNetCore.Mvc.ObjectResult MfaRequired()
        => new(new { mfaRequired = true }) { StatusCode = StatusCodes.Status403Forbidden };

    /// <summary>Bearer（OpenIddict Validation 方案）+ admin 角色（按 claim 短名断言，见 Program.cs 注册处注释）。</summary>
    public const string PolicyName = "admin-api";

    /// <summary>
    /// 会话探针专用轻量策略：仅要求已认证（admin-api 主策略额外要求 TOTP 绑定，
    /// 未绑定者需经 /admin-api/session 拿到引导信号，不能被主策略一并挡死）。
    /// </summary>
    public const string SessionPolicyName = "admin-api-session";

    /// <summary>普通写操作必须有八小时内完成的任一 MFA；只读 GET 不使用此门禁。</summary>
    public static bool HasValidMfa(System.Security.Claims.ClaimsPrincipal principal)
        => Infrastructure.Security.Mfa.RecentMfaRequirement.HasValidMfa(principal, DateTimeOffset.UtcNow, TimeSpan.FromHours(8));
}

internal sealed class AdminResourceRequirement : IAuthorizationRequirement;

/// <summary>
/// admin-api 主策略：身份/角色/状态之外，还要求操作者已绑定已确认 TOTP——
/// Passkey 退役后（AUTH-DELIVERY-002），未完成 TOTP 绑定的管理员不得取得任何管理能力；
/// 绑定引导信号由不走本策略的 /admin-api/session 提供。
/// </summary>
internal sealed class AdminResourceHandler(
    UserService users,
    Infrastructure.Persistence.PandaAuthDbContext db) : AuthorizationHandler<AdminResourceRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminResourceRequirement requirement)
    {
        if (!AdminApiAuthorization.HasResource(context.User)) return;
        var subject = context.User.GetClaim(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrEmpty(subject)) return;
        var user = await users.FindByIdAsync(subject);
        if (user?.Status != UserStatus.Active) return;
        var totpBound = await db.TotpFactors.AnyAsync(factor =>
            factor.UserId == subject && factor.RevokedAt == null && factor.ConfirmedAt != null,
            CancellationToken.None);
        if (totpBound) context.Succeed(requirement);
    }
}
