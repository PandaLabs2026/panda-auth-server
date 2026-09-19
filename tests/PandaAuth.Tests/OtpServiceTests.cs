using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// OtpService 全生命周期测试（口径移植自 panda-asst，行为断言在 PandaAuth 重写）：
/// 哈希入库、消费、过期、双频控、失败锁定。FakeTimeProvider 控制时间推进。
/// </summary>
public class OtpServiceTests
{
    private sealed class FakeTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-09-19T12:00:00Z");

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static (OtpService Service, PandaAuthDbContext Db, FakeTimeProvider Time) Create()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PandaAuthDbContext>(builder => builder.UseInMemoryDatabase(Guid.NewGuid().ToString("N")));
        var provider = services.BuildServiceProvider();
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var time = new FakeTimeProvider();
        return (new OtpService(db, time), db, time);
    }

    [Fact]
    public async Task Issue_StoresHashOnly_PlaintextNeverInDb()
    {
        var (service, db, _) = Create();

        var code = await service.IssueAsync("User@Example.com", CancellationToken.None);

        var row = Assert.Single(db.VerificationCodes.AsEnumerable());
        // 明文验证码绝不入库；键为规范化小写邮箱的哈希。
        Assert.Equal(VerificationHasher.CodeHash(code), row.CodeHash);
        Assert.NotEqual(code, row.CodeHash);
        Assert.Equal(VerificationHasher.EmailHash("User@Example.com"), row.EmailHash);
        Assert.Null(row.ConsumedAt);
    }

    [Fact]
    public async Task Verify_CorrectCode_SucceedsAndConsumes()
    {
        var (service, db, _) = Create();
        var code = await service.IssueAsync("a@example.com", CancellationToken.None);

        Assert.Equal(OtpVerifyOutcome.Success, await service.VerifyAsync("a@example.com", code, CancellationToken.None));
        // 已消费的码不能复用（防重放）。
        Assert.Equal(OtpVerifyOutcome.MissingOrExpired, await service.VerifyAsync("a@example.com", code, CancellationToken.None));
        // 大小写与首尾空白不影响检索（规范化哈希）。
        Assert.Single(db.VerificationCodes.AsEnumerable());
    }

    [Fact]
    public async Task Verify_WrongCode_IncrementsFailures_ThenLocks()
    {
        var (service, db, _) = Create();
        await service.IssueAsync("a@example.com", CancellationToken.None);

        // 锁定判定发生在失败计数递增之前（asst 口径）：第 5 次错误本身仍是 InvalidCode，
        // 之后的任何尝试（无论对错）才进入 Locked。
        for (var i = 1; i <= OtpService.MaxFailures; i++)
        {
            Assert.Equal(OtpVerifyOutcome.InvalidCode, await service.VerifyAsync("a@example.com", "000000", CancellationToken.None));
        }

        Assert.Equal(OtpVerifyOutcome.Locked, await service.VerifyAsync("a@example.com", "000000", CancellationToken.None));
    }

    [Fact]
    public async Task Verify_ExpiredCode_ReturnsMissingOrExpired()
    {
        var (service, _, time) = Create();
        var code = await service.IssueAsync("a@example.com", CancellationToken.None);

        time.Now = time.Now.AddMinutes(OtpService.CodeTtlMinutes + 1);
        Assert.Equal(OtpVerifyOutcome.MissingOrExpired, await service.VerifyAsync("a@example.com", code, CancellationToken.None));
    }

    [Fact]
    public async Task Issue_RateLimited_OnePerMinute()
    {
        var (service, _, _) = Create();
        await service.IssueAsync("a@example.com", CancellationToken.None);

        await Assert.ThrowsAsync<OtpRateLimitedException>(
            () => service.IssueAsync("a@example.com", CancellationToken.None));
    }

    [Fact]
    public async Task Issue_RateLimited_FivePerHour_AfterMinuteWindowPasses()
    {
        var (service, _, time) = Create();
        for (var i = 0; i < 5; i++)
        {
            await service.IssueAsync("a@example.com", CancellationToken.None);
            time.Now = time.Now.AddMinutes(2); // 跨过 1 分钟窗口，只触发小时上限
        }

        await Assert.ThrowsAsync<OtpRateLimitedException>(
            () => service.IssueAsync("a@example.com", CancellationToken.None));
    }

    [Fact]
    public async Task Issue_DifferentEmails_IndependentRateLimits()
    {
        var (service, _, _) = Create();
        await service.IssueAsync("a@example.com", CancellationToken.None);
        // 另一个邮箱不受第一个邮箱的频控影响。
        await service.IssueAsync("b@example.com", CancellationToken.None);
    }

    [Fact]
    public async Task Retention_PurgesVerificationCodes()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PandaAuthDbContext>(builder => builder.UseInMemoryDatabase(Guid.NewGuid().ToString("N")));
        var provider = services.BuildServiceProvider();
        var db = provider.GetRequiredService<PandaAuthDbContext>();

        db.VerificationCodes.AddRange(
            new VerificationCode { EmailHash = "h", CodeHash = "c", CreatedAt = DateTimeOffset.Parse("2026-09-01T00:00:00Z"), ExpiresAt = DateTimeOffset.Parse("2026-09-01T00:05:00Z") },
            new VerificationCode { EmailHash = "h", CodeHash = "c", CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-1), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(4) });
        await db.SaveChangesAsync();

        var removed = await LoginLogRetentionService.PurgeVerificationCodesAsync(db, CancellationToken.None);

        Assert.Equal(1, removed);
        Assert.Single(db.VerificationCodes.AsEnumerable());
    }
}
