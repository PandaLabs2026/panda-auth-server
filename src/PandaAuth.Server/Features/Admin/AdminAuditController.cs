using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Admin;

/// <summary>审计查询（只读）：登录日志与管理操作日志，均带时间过滤与分页。</summary>
[Route("~/admin-api/audit")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = AdminApiAuthorization.PolicyName)]
public sealed class AdminAuditController(PandaAuthDbContext dbContext) : Controller
{
    internal const int MaxPageSize = 50;
    internal const int DefaultPageSize = 20;

    [HttpGet("logins")]
    public async Task<IActionResult> Logins(
        [FromQuery] string? userName,
        [FromQuery] bool? succeeded,
        [FromQuery] DateTimeOffset? from,
        [FromQuery] DateTimeOffset? to,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var (pageNumber, size) = NormalizePaging(page, pageSize);
        var logs = dbContext.LoginLogs.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(userName))
        {
            logs = logs.Where(log => log.UserName.Contains(userName.Trim()));
        }

        if (succeeded is { } succeededFilter)
        {
            logs = logs.Where(log => log.Succeeded == succeededFilter);
        }

        if (from is { } fromValue)
        {
            logs = logs.Where(log => log.CreatedAt >= fromValue);
        }

        if (to is { } toValue)
        {
            logs = logs.Where(log => log.CreatedAt <= toValue);
        }

        var total = await logs.CountAsync(cancellationToken);
        var items = await logs
            .OrderByDescending(log => log.CreatedAt)
            .ThenBy(log => log.Id)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .Select(log => new AdminLoginLogEntry(
                log.Id, log.UserId, log.UserName, log.ClientId, log.IpAddress, log.UserAgent,
                log.Succeeded, log.FailureReason, log.CreatedAt))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminLoginLogEntry>(items, total, pageNumber, size));
    }

    [HttpGet("admin")]
    public async Task<IActionResult> Admin(
        [FromQuery] string? actor,
        [FromQuery] string? action,
        [FromQuery] DateTimeOffset? from,
        [FromQuery] DateTimeOffset? to,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var (pageNumber, size) = NormalizePaging(page, pageSize);
        var logs = dbContext.AdminAuditLogs.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(actor))
        {
            var actorFilter = actor.Trim();
            logs = logs.Where(log =>
                (log.ActorUserName != null && log.ActorUserName.Contains(actorFilter))
                || log.ActorUserId.Contains(actorFilter));
        }

        if (!string.IsNullOrWhiteSpace(action))
        {
            logs = logs.Where(log => log.Action == action);
        }

        if (from is { } fromValue)
        {
            logs = logs.Where(log => log.CreatedAt >= fromValue);
        }

        if (to is { } toValue)
        {
            logs = logs.Where(log => log.CreatedAt <= toValue);
        }

        var total = await logs.CountAsync(cancellationToken);
        var items = await logs
            .OrderByDescending(log => log.CreatedAt)
            .ThenBy(log => log.Id)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .Select(log => new AdminAuditLogEntry(
                log.Id, log.ActorUserId, log.ActorUserName, log.Action,
                log.TargetType, log.TargetId, log.Detail, log.IpAddress, log.CreatedAt))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminAuditLogEntry>(items, total, pageNumber, size));
    }

    private static (int Page, int PageSize) NormalizePaging(int? page, int? pageSize)
        => (Math.Max(page ?? 1, 1), Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize));
}
