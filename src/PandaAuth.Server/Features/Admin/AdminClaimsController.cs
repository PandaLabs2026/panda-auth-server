using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 自定义 Claims 管理控制面。Claims 只允许通过 ClaimsPolicyService 写入，避免管理端绕过
/// panda:* 命名空间、scope 绑定和保留 Claim 校验。
/// </summary>
[Route("~/admin-api/claims")]
[RequireConfirmedEmail]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = AdminApiAuthorization.PolicyName)]
public sealed class AdminClaimsController(
    PandaAuthDbContext db,
    ClaimsPolicyService claims,
    AdminAuditWriter audit,
    SecurityEventWriter securityEvents) : Controller
{
    [HttpGet("users/{userId}")]
    public async Task<IActionResult> ListUser(string userId)
    {
        if (!await db.Users.AnyAsync(user => user.Id == userId)) return NotFound();
        var items = (await claims.GetUserClaimsAsync(userId))
            .Select(claim => new AdminUserClaimEntry(
                claim.Id, claim.UserId, claim.ClaimType, claim.ClaimValue, claim.Scope))
            .ToArray();
        return Ok(items);
    }

    [HttpPost("users/{userId}")]
    public async Task<IActionResult> AddUser(string userId, [FromBody] AdminClaimRequest? request, CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasRecentWebAuthn(User)) return Forbid();
        if (request is null) return Problem(statusCode: StatusCodes.Status400BadRequest, title: "请求体缺失");

        var result = await claims.AddUserClaimAsync(userId, request.ClaimType, request.ClaimValue, request.Scope);
        if (!result.Succeeded) return ResultError(result);
        var claim = await db.UserClaims.AsNoTracking().SingleAsync(item =>
            item.UserId == userId && item.ClaimType == request.ClaimType &&
            item.ClaimValue == request.ClaimValue && item.Scope == request.Scope, cancellationToken);

        await RecordAsync(AdminAuditAction.UserAddClaim, "user.add_claim", "user", userId,
            new { claim.ClaimType, claim.ClaimValue, claim.Scope }, cancellationToken);
        return Created(PandaAuthAdminApi.UserClaim(userId, claim.Id),
            new AdminUserClaimEntry(claim.Id, claim.UserId, claim.ClaimType, claim.ClaimValue, claim.Scope));
    }

    [HttpDelete("users/{userId}/{claimId:long}")]
    public async Task<IActionResult> RemoveUser(string userId, long claimId, CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasRecentWebAuthn(User)) return Forbid();
        var claim = await db.UserClaims.SingleOrDefaultAsync(item => item.Id == claimId && item.UserId == userId, cancellationToken);
        if (claim is null) return NotFound();
        var detail = new { claim.ClaimType, claim.ClaimValue, claim.Scope };
        var result = await claims.RemoveUserClaimAsync(userId, claimId);
        if (!result.Succeeded) return ResultError(result);

        await RecordAsync(AdminAuditAction.UserRemoveClaim, "user.remove_claim", "user", userId, detail, cancellationToken);
        return NoContent();
    }

    [HttpGet("roles/{roleId}")]
    public async Task<IActionResult> ListRole(string roleId)
    {
        if (!await db.Roles.AnyAsync(role => role.Id == roleId)) return NotFound();
        var items = (await claims.GetRoleClaimsAsync(roleId))
            .Select(claim => new AdminRoleClaimEntry(
                claim.Id, claim.RoleId, claim.ClaimType, claim.ClaimValue, claim.Scope))
            .ToArray();
        return Ok(items);
    }

    [HttpPost("roles/{roleId}")]
    public async Task<IActionResult> AddRole(string roleId, [FromBody] AdminClaimRequest? request, CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasRecentWebAuthn(User)) return Forbid();
        if (request is null) return Problem(statusCode: StatusCodes.Status400BadRequest, title: "请求体缺失");

        var result = await claims.AddRoleClaimAsync(roleId, request.ClaimType, request.ClaimValue, request.Scope);
        if (!result.Succeeded) return ResultError(result);
        var claim = await db.RoleClaims.AsNoTracking().SingleAsync(item =>
            item.RoleId == roleId && item.ClaimType == request.ClaimType &&
            item.ClaimValue == request.ClaimValue && item.Scope == request.Scope, cancellationToken);

        await RecordAsync(AdminAuditAction.RoleAddClaim, "role.add_claim", "role", roleId,
            new { claim.ClaimType, claim.ClaimValue, claim.Scope }, cancellationToken);
        return Created(PandaAuthAdminApi.RoleClaim(roleId, claim.Id),
            new AdminRoleClaimEntry(claim.Id, claim.RoleId, claim.ClaimType, claim.ClaimValue, claim.Scope));
    }

    [HttpDelete("roles/{roleId}/{claimId:long}")]
    public async Task<IActionResult> RemoveRole(string roleId, long claimId, CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasRecentWebAuthn(User)) return Forbid();
        var claim = await db.RoleClaims.SingleOrDefaultAsync(item => item.Id == claimId && item.RoleId == roleId, cancellationToken);
        if (claim is null) return NotFound();
        var detail = new { claim.ClaimType, claim.ClaimValue, claim.Scope };
        var result = await claims.RemoveRoleClaimAsync(roleId, claimId);
        if (!result.Succeeded) return ResultError(result);

        await RecordAsync(AdminAuditAction.RoleRemoveClaim, "role.remove_claim", "role", roleId, detail, cancellationToken);
        return NoContent();
    }

    private async Task RecordAsync(
        string auditAction,
        string eventType,
        string targetType,
        string targetId,
        object detail,
        CancellationToken cancellationToken)
    {
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, auditAction, targetType, targetId, detail,
                HttpContext.Connection.RemoteIpAddress?.ToString()), cancellationToken);
        await securityEvents.RecordAsync(new SecurityEventEntry(
            eventType,
            targetType == "user" ? targetId : null,
            User.FindFirst("sub")?.Value,
            targetType,
            targetId,
            "admin_webauthn",
            detail,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent.ToString(),
            HttpContext.TraceIdentifier), cancellationToken);
    }

    private IActionResult ResultError(AccountResult result)
    {
        var error = result.Errors.FirstOrDefault();
        var status = error?.Code is "UserNotFound" or "RoleNotFound" or "ClaimNotFound"
            ? StatusCodes.Status404NotFound : StatusCodes.Status400BadRequest;
        return Problem(statusCode: status, title: error?.Code ?? "ClaimOperationFailed", detail: error?.Description);
    }
}
