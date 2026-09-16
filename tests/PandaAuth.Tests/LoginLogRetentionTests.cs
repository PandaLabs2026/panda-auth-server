using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// login_logs 保留策略：只删除 CreatedAt 早于截止点的记录。
/// 不用真实计时器驱动后台循环，直接断言清理逻辑本身。
/// </summary>
public class LoginLogRetentionTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 16, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Purge_DeletesOnlyRecordsOlderThanCutoff()
    {
        await using var dbContext = CreateContext();
        dbContext.LoginLogs.AddRange(
            NewLog("expired-far", Now.AddDays(-120)),
            NewLog("expired-edge", Now.AddDays(-91)),
            NewLog("kept-edge", Now.AddDays(-89)),
            NewLog("kept-today", Now));

        await dbContext.SaveChangesAsync();

        var cutoff = LoginLogRetentionService.ComputeCutoff(Now, retentionDays: 90);
        var removed = await LoginLogRetentionService.PurgeAsync(
            dbContext, cutoff, LoginLogRetentionService.BatchSize, CancellationToken.None);

        Assert.Equal(2, removed);
        var remaining = await dbContext.LoginLogs.OrderBy(log => log.Id).Select(log => log.UserName).ToListAsync();
        Assert.Equal(["kept-edge", "kept-today"], remaining);
    }

    [Fact]
    public async Task Purge_DeletesInBatches_UntilNoExpiredRecordRemains()
    {
        await using var dbContext = CreateContext();
        for (var index = 0; index < 7; index++)
        {
            dbContext.LoginLogs.Add(NewLog($"expired-{index}", Now.AddDays(-100 - index)));
        }

        dbContext.LoginLogs.Add(NewLog("kept", Now));
        await dbContext.SaveChangesAsync();

        // 每批 2 行：验证循环会持续到清空全部超期记录，而不是只删一批。
        var removed = await LoginLogRetentionService.PurgeAsync(
            dbContext, LoginLogRetentionService.ComputeCutoff(Now, 90), batchSize: 2, CancellationToken.None);

        Assert.Equal(7, removed);
        Assert.Equal(["kept"], await dbContext.LoginLogs.Select(log => log.UserName).ToListAsync());
    }

    [Fact]
    public async Task Purge_WithNothingExpired_DeletesNothing()
    {
        await using var dbContext = CreateContext();
        dbContext.LoginLogs.Add(NewLog("kept", Now));
        await dbContext.SaveChangesAsync();

        var removed = await LoginLogRetentionService.PurgeAsync(
            dbContext, LoginLogRetentionService.ComputeCutoff(Now, 90), LoginLogRetentionService.BatchSize,
            CancellationToken.None);

        Assert.Equal(0, removed);
        Assert.Equal(1, await dbContext.LoginLogs.CountAsync());
    }

    [Fact]
    public void ComputeCutoff_SubtractsRetentionDays()
    {
        Assert.Equal(Now.AddDays(-90), LoginLogRetentionService.ComputeCutoff(Now, 90));
        Assert.Equal(Now.AddDays(-1), LoginLogRetentionService.ComputeCutoff(Now, 1));
    }

    private static PandaAuthDbContext CreateContext() => new(
        new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options);

    private static LoginLog NewLog(string userName, DateTimeOffset createdAt) => new()
    {
        UserName = userName,
        CreatedAt = createdAt,
        Succeeded = false,
        FailureReason = "wrong_password",
    };
}
