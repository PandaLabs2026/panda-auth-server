using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// login_logs 保留策略：只删除 CreatedAt 早于截止点的记录，保留天数误配时拒绝执行。
/// 不用真实计时器驱动后台循环，直接断言清理逻辑与后台服务的启动行为。
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

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task NonPositiveRetentionDays_DoesNotDeleteAnything_AndWarns(int retentionDays)
    {
        // 「别把审计删光」的守卫：非正数视为误配，任务拒绝执行（否则 AddDays(-0)/AddDays(5) 会删掉全部记录）。
        var logger = new RecordingLogger();
        using var provider = CreateServiceProvider();
        await SeedAsync(provider, expired: 2, fresh: 1);

        var service = new LoginLogRetentionService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new AuthOptions { Audit = new AuditOptions { RetentionDays = retentionDays } }),
            logger);

        await service.StartAsync(CancellationToken.None);

        // ExecuteAsync 由 StartAsync 调度执行，不保证同步跑完（实测其 ExecuteTask 先处于
        // WaitingForActivation），因此这里轮询等待告警。注意不能先 StopAsync：先取消会让尚未开始的
        // 调度任务直接以取消收场而不执行，告警也就不会出现。
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!logger.Messages.Any(message => message.Level == LogLevel.Warning) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        await service.StopAsync(CancellationToken.None);

        Assert.Equal(3, await CountAsync(provider));
        Assert.Contains(logger.Messages, message => message.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task PositiveRetentionDays_PurgesExpiredRecordsOnStartup()
    {
        var logger = new RecordingLogger();
        using var provider = CreateServiceProvider();
        await SeedAsync(provider, expired: 2, fresh: 1);

        var service = new LoginLogRetentionService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new AuthOptions { Audit = new AuditOptions { RetentionDays = 90 } }),
            logger);

        await service.StartAsync(CancellationToken.None);
        // StartAsync 不等待首轮清理完成，轮询到清理生效后再停（StopAsync 会取消 24 小时等待）。
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (await CountAsync(provider) > 1 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50);
        }

        await service.StopAsync(CancellationToken.None);

        Assert.Equal(1, await CountAsync(provider));
    }

    private static ServiceProvider CreateServiceProvider()
    {
        // 库名必须在 lambda 外生成：options lambda 每个作用域都会执行一次，
        // 写在里面会让每个作用域拿到一个独立空库（后台服务在自己的作用域里就看不到种子数据）。
        var databaseName = Guid.NewGuid().ToString("N");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PandaAuthDbContext>(builder => builder.UseInMemoryDatabase(databaseName));
        return services.BuildServiceProvider();
    }

    private static async Task SeedAsync(ServiceProvider provider, int expired, int fresh)
    {
        var dbContext = provider.GetRequiredService<PandaAuthDbContext>();
        for (var index = 0; index < expired; index++)
        {
            dbContext.LoginLogs.Add(NewLog($"expired-{index}", DateTimeOffset.UtcNow.AddDays(-120 - index)));
        }

        for (var index = 0; index < fresh; index++)
        {
            dbContext.LoginLogs.Add(NewLog($"fresh-{index}", DateTimeOffset.UtcNow.AddDays(-1)));
        }

        await dbContext.SaveChangesAsync();
    }

    private static async Task<int> CountAsync(ServiceProvider provider)
        => await provider.GetRequiredService<PandaAuthDbContext>().LoginLogs.CountAsync();

    /// <summary>记录日志级别的替身，用于断言误配时确实告警。</summary>
    private sealed class RecordingLogger : ILogger<LoginLogRetentionService>
    {
        public List<(LogLevel Level, string Message)> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Messages.Add((logLevel, formatter(state, exception)));
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
