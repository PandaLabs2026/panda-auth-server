using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 通知中心（读侧）：管理审计流的派生视图 + 每管理员已读水位。
/// 一期通知源=审计流本身（只记变更不记读），本控制器不写审计表——列表纯只读；
/// 游标写入只碰 admin_notification_cursors，无业务变更语义，故不设 MFA 步进门
/// （与审计查询同授权档：Bearer + admin-api 策略）。
/// </summary>
[Route("~/admin-api/notifications")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = AdminApiAuthorization.PolicyName)]
public sealed class AdminNotificationsController(PandaAuthDbContext dbContext) : Controller
{
    internal const int MaxPageSize = 50;
    internal const int DefaultPageSize = 20;

    /// <summary>通知列表：按审计 Id 倒序（Id 单调递增，与游标语义同轴：Id 大于游标即未读）。</summary>
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var (pageNumber, size) = NormalizePaging(page, pageSize);
        var logs = dbContext.AdminAuditLogs.AsNoTracking();

        var total = await logs.CountAsync(cancellationToken);
        var items = await logs
            .OrderByDescending(log => log.Id)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .Select(log => new AdminNotificationEntry(
                log.Id, log.ActorUserId, log.ActorUserName, log.Action,
                log.TargetType, log.TargetId, log.Detail, log.IpAddress, log.CreatedAt))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminNotificationEntry>(items, total, pageNumber, size));
    }

    /// <summary>当前管理员的已读水位；无记录时为 0（全部条目按未读计）。</summary>
    [HttpGet("cursor")]
    public async Task<IActionResult> GetCursor(CancellationToken cancellationToken)
    {
        var adminUserId = AdminUserId();
        var cursor = await dbContext.AdminNotificationCursors.AsNoTracking()
            .SingleOrDefaultAsync(row => row.AdminUserId == adminUserId, cancellationToken);
        return Ok(new AdminSeenCursor(cursor?.LastAuditId ?? 0));
    }

    /// <summary>游标写入：单调不回退（小于等于现值直接幂等返回现值）。</summary>
    [HttpPost("cursor")]
    public async Task<IActionResult> SetCursor(
        [FromBody] AdminSeenCursorRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null || request.LastAuditId < 0)
        {
            return Problem(statusCode: 400, title: "游标无效", detail: "LastAuditId 必须是非负整数。");
        }

        var adminUserId = AdminUserId();
        var cursor = await dbContext.AdminNotificationCursors
            .SingleOrDefaultAsync(row => row.AdminUserId == adminUserId, cancellationToken);

        if (cursor is null)
        {
            dbContext.AdminNotificationCursors.Add(new AdminNotificationCursor
            {
                AdminUserId = adminUserId,
                LastAuditId = request.LastAuditId,
                UpdatedAt = DateTimeOffset.UtcNow,
            });
        }
        else if (request.LastAuditId > cursor.LastAuditId)
        {
            cursor.LastAuditId = request.LastAuditId;
            cursor.UpdatedAt = DateTimeOffset.UtcNow;
        }
        // 回退写入：幂等忽略（不报错——「全部已读」后晚到的旧游标上报不该翻红）。

        await dbContext.SaveChangesAsync(cancellationToken);
        var final = await dbContext.AdminNotificationCursors.AsNoTracking()
            .SingleAsync(row => row.AdminUserId == adminUserId, cancellationToken);
        return Ok(new AdminSeenCursor(final.LastAuditId));
    }

    private string AdminUserId() => User.FindFirst(Claims.Subject)?.Value ?? string.Empty;

    private static (int Page, int PageSize) NormalizePaging(int? page, int? pageSize)
        => (Math.Max(page ?? 1, 1), Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize));
}
