using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// 审计日志保留策略：按天删除超过保留期的 <c>login_logs</c> 与 <c>admin_audit_logs</c> 记录。
/// 登录日志每次尝试（含失败）都同步写一行、管理日志每次变更写一行，且无分区、无保留期，
/// 长期运行会被无界撑大。两类表共用同一保留期口径。
/// </summary>
/// <remarks>
/// 口径（同时记录在 deploy/README.md，供运维核对）：
/// 保留 <see cref="AuditOptions.RetentionDays"/> 天（配置 <c>Auth:Audit:RetentionDays</c>，默认 90），
/// 删除 <c>CreatedAt</c> 早于「当前时间 - 保留天数」的记录，分批删除以避免长事务与长时间持锁。
/// 进程启动后立即执行一次，此后每 24 小时一次；保留天数配置为非正数时拒绝执行并告警。
/// </remarks>
public sealed class LoginLogRetentionService(
    IServiceScopeFactory scopeFactory,
    IOptions<AuthOptions> options,
    ILogger<LoginLogRetentionService> logger) : BackgroundService
{
    /// <summary>单批删除行数。</summary>
    internal const int BatchSize = 500;

    /// <summary>清理周期。</summary>
    internal static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var retentionDays = options.Value.Audit.RetentionDays;
        if (retentionDays <= 0)
        {
            logger.LogWarning(
                "登录审计日志保留天数配置非法（Auth:Audit:RetentionDays={RetentionDays}），清理任务不执行；请改为正数并重启。",
                retentionDays);
            return;
        }

        logger.LogInformation(
            "登录审计日志保留策略：保留最近 {RetentionDays} 天（Auth:Audit:RetentionDays），启动时及每 {IntervalHours} 小时删除 login_logs 中 CreatedAt 早于截止点的记录，每批 {BatchSize} 行。",
            retentionDays, (int)Interval.TotalHours, BatchSize);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                var cutoff = ComputeCutoff(DateTimeOffset.UtcNow, retentionDays);
                var removed = await PurgeAsync(dbContext, cutoff, BatchSize, stoppingToken);
                var removedAdmin = await PurgeAdminAuditAsync(dbContext, cutoff, BatchSize, stoppingToken);
                logger.LogInformation(
                    "审计日志清理完成：login_logs 删除 {Removed} 行、admin_audit_logs 删除 {RemovedAdmin} 行，截止点 {Cutoff:O}。",
                    removed, removedAdmin, cutoff);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // 单次清理失败（例如数据库暂时不可用）不能让后台任务退出，否则保留策略就此静默失效。
                logger.LogError(exception, "登录审计日志清理失败，将在下一周期重试。");
            }

            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>截止点：早于该时刻的记录视为超期。</summary>
    internal static DateTimeOffset ComputeCutoff(DateTimeOffset now, int retentionDays)
        => now.AddDays(-retentionDays);

    /// <summary>
    /// 分批删除超期记录，返回删除行数。
    /// 用「查询 + RemoveRange」而非 ExecuteDelete：EF InMemory（单元测试所用提供程序）不支持批量删除 API，
    /// 且分批删除本身就需要限定行数。
    /// </summary>
    internal static async Task<int> PurgeAsync(
        PandaAuthDbContext dbContext, DateTimeOffset cutoff, int batchSize, CancellationToken cancellationToken)
    {
        var removed = 0;
        while (true)
        {
            var expired = await dbContext.LoginLogs
                .Where(log => log.CreatedAt < cutoff)
                .OrderBy(log => log.Id)
                .Take(batchSize)
                .ToListAsync(cancellationToken);
            if (expired.Count == 0)
            {
                return removed;
            }

            dbContext.LoginLogs.RemoveRange(expired);
            await dbContext.SaveChangesAsync(cancellationToken);
            removed += expired.Count;

            if (expired.Count < batchSize)
            {
                return removed;
            }
        }
    }

    /// <summary>管理操作审计的同类分批删除（同 PurgeAsync 的实现约束：EF InMemory 不支持批量删除 API）。</summary>
    internal static async Task<int> PurgeAdminAuditAsync(
        PandaAuthDbContext dbContext, DateTimeOffset cutoff, int batchSize, CancellationToken cancellationToken)
    {
        var removed = 0;
        while (true)
        {
            var expired = await dbContext.AdminAuditLogs
                .Where(log => log.CreatedAt < cutoff)
                .OrderBy(log => log.Id)
                .Take(batchSize)
                .ToListAsync(cancellationToken);
            if (expired.Count == 0)
            {
                return removed;
            }

            dbContext.AdminAuditLogs.RemoveRange(expired);
            await dbContext.SaveChangesAsync(cancellationToken);
            removed += expired.Count;

            if (expired.Count < batchSize)
            {
                return removed;
            }
        }
    }
}
