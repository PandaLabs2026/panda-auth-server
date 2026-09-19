using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 用户管理数据 API（webadmin BFF 专用，Bearer + admin 角色；路径不经公网）。
/// 冻结与重置密码都联动批量吊销：令牌即时失效是 G06 的生效边界要求。
/// </summary>
[Route("~/admin-api/users")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = AdminApiAuthorization.PolicyName)]
public sealed class AdminUsersController(
    UserManager<PandaAuthUser> userManager,
    ITokenRevoker tokenRevoker,
    AdminAuditWriter audit,
    ILogger<AdminUsersController> logger) : Controller
{
    internal const int MaxPageSize = 50;
    internal const int DefaultPageSize = 20;

    /// <summary>用户列表：按用户名/邮箱模糊搜索、状态过滤、分页（CreatedAt 倒序）。</summary>
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] string? query,
        [FromQuery] UserStatus? status,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var pageNumber = Math.Max(page ?? 1, 1);
        var size = Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize);

        var users = userManager.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query))
        {
            // 与 Identity 的默认规范化器（UpperInvariant）一致，大小写不敏感搜索。
            var normalized = query.Trim().ToUpperInvariant();
            users = users.Where(user =>
                user.NormalizedUserName!.Contains(normalized)
                || (user.NormalizedEmail != null && user.NormalizedEmail.Contains(normalized)));
        }

        if (status is { } statusFilter)
        {
            users = users.Where(user => user.Status == statusFilter);
        }

        var total = await users.CountAsync(cancellationToken);
        var items = await users
            .OrderByDescending(user => user.CreatedAt)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .Select(user => new AdminUserSummary(
                user.Id, user.UserName!, user.Email, user.Nickname, user.Status, user.CreatedAt))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminUserSummary>(items, total, pageNumber, size));
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Detail(string id)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        var roles = await userManager.GetRolesAsync(user);
        return Ok(new AdminUserDetail(
            user.Id, user.UserName!, user.Email, user.EmailConfirmed, user.Nickname, user.Status,
            [.. roles], user.LockoutEnd, user.AccessFailedCount, user.TwoFactorEnabled,
            user.RegisterChannel, user.Region, user.CreatedAt, user.UpdatedAt));
    }

    /// <summary>冻结 / 解冻。幂等：状态未变化时不产生吊销与审计。冻结后该用户全部有效令牌即时吊销。</summary>
    [HttpPost("{id}/status")]
    public async Task<IActionResult> SetStatus(
        string id,
        [FromBody] AdminUserStatusRequest? request,
        CancellationToken cancellationToken)
    {
        // Deleted 是注销语义（软删除），不经本端点设置，防止管理台误触不可逆状态。
        if (request is null || request.Status is not (UserStatus.Active or UserStatus.Frozen))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "无效的状态变更",
                detail: "status 只接受 Active 或 Frozen。");
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (user.Status == request.Status)
        {
            return Ok(SummaryOf(user));
        }

        var previous = user.Status;
        user.Status = request.Status;
        user.UpdatedAt = DateTimeOffset.UtcNow;
        var update = await userManager.UpdateAsync(user);
        if (!update.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "状态更新失败",
                detail: string.Join("; ", update.Errors.Select(error => error.Description)));
        }

        await tokenRevoker.RevokeUserTokensAsync(user.Id, cancellationToken: cancellationToken);
        var action = request.Status == UserStatus.Frozen ? AdminAuditAction.UserFreeze : AdminAuditAction.UserUnfreeze;
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, action, "user", user.Id,
                new { userName = user.UserName, from = previous.ToString(), to = request.Status.ToString() },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 将用户 {UserId}（{UserName}）状态由 {Previous} 变更为 {Status}。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName, previous, request.Status);

        return Ok(SummaryOf(user));
    }

    /// <summary>
    /// 重置密码：不传 NewPassword 则服务端生成合规随机密码；明文仅本次响应返回一次。
    /// 成功后吊销该用户全部令牌并刷新安全戳（Cookie 会话随之失效）。
    /// </summary>
    [HttpPost("{id}/reset-password")]
    public async Task<IActionResult> ResetPassword(
        string id,
        [FromBody] AdminResetPasswordRequest? request,
        CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        var generated = string.IsNullOrEmpty(request?.NewPassword);
        var password = generated ? AdminPasswordGenerator.Generate() : request!.NewPassword!;

        // 先留底再移除：AddPasswordAsync 若因策略不过而失败，此时用户已无密码，
        // 不回滚旧哈希会把账号锁死在「无密码」状态（谁也登不进，包括管理员重置）。
        var originalHash = user.PasswordHash;
        var remove = await userManager.RemovePasswordAsync(user);
        if (!remove.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "移除旧密码失败",
                detail: string.Join("; ", remove.Errors.Select(error => error.Description)));
        }

        var add = await userManager.AddPasswordAsync(user, password);
        if (!add.Succeeded)
        {
            user.PasswordHash = originalHash;
            await userManager.UpdateAsync(user);
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "新密码不合规",
                detail: string.Join("; ", add.Errors.Select(error => error.Description)));
        }

        await userManager.UpdateSecurityStampAsync(user);
        await tokenRevoker.RevokeUserTokensAsync(user.Id, cancellationToken: cancellationToken);
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserResetPassword, "user", user.Id,
                new { userName = user.UserName, generated }, HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 重置了用户 {UserId}（{UserName}）的密码。", User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName);

        return Ok(new AdminResetPasswordResponse(password));
    }

    private static AdminUserSummary SummaryOf(PandaAuthUser user)
        => new(user.Id, user.UserName!, user.Email, user.Nickname, user.Status, user.CreatedAt);
}
