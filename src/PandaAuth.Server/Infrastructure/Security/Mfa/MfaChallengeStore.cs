using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public sealed record ConsumedMfaChallenge(byte[] Value, DateTimeOffset ExpiresAt);

/// <summary>
/// WebAuthn ceremony 的服务端一次性状态存储，落在 <c>panda_mfa_challenges</c>。
/// 消费用条件 UPDATE 原子完成：进程内锁无法跨实例，条件更新天然多实例安全，
/// 也是容器重建后 ceremony 仍可继续的基础。过期行由 LoginLogRetentionService 回收。
/// </summary>
public sealed class MfaChallengeStore(PandaAuthDbContext db, TimeProvider clock)
{
    public async Task<Guid> CreateAsync(
        string purpose,
        string subject,
        byte[] value,
        TimeSpan lifetime,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
        cancellationToken.ThrowIfCancellationRequested();

        var id = Guid.NewGuid();
        db.MfaChallenges.Add(new MfaChallenge
        {
            Id = id,
            Purpose = purpose,
            SubjectId = subject,
            Value = [.. value],
            ExpiresAt = clock.GetUtcNow().Add(lifetime),
        });
        await db.SaveChangesAsync(cancellationToken);
        return id;
    }

    public async Task<ConsumedMfaChallenge?> ConsumeAsync(
        Guid id,
        string purpose,
        string subject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = clock.GetUtcNow();
        if (db.Database.IsRelational())
        {
            var consumedAt = now;
            var claimed = await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE panda_mfa_challenges SET "ConsumedAt" = {consumedAt}
                WHERE "Id" = {id} AND "Purpose" = {purpose} AND "SubjectId" = {subject}
                  AND "ConsumedAt" IS NULL AND "ExpiresAt" > {now}
                """, cancellationToken);
            db.ChangeTracker.Clear();
            if (claimed != 1) return null;
            var row = await db.MfaChallenges.AsNoTracking()
                .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
            return row is null ? null : new ConsumedMfaChallenge(row.Value, row.ExpiresAt);
        }

        // EF InMemory（测试提供程序）不支持原生 SQL；单次消费语义相同，
        // 并发安全只由关系型分支的条件 UPDATE 保证。
        var stored = await db.MfaChallenges.SingleOrDefaultAsync(
            item => item.Id == id && item.Purpose == purpose && item.SubjectId == subject, cancellationToken);
        if (stored is null || stored.ConsumedAt is not null || stored.ExpiresAt <= now) return null;
        stored.ConsumedAt = now;
        await db.SaveChangesAsync(cancellationToken);
        return new ConsumedMfaChallenge(stored.Value, stored.ExpiresAt);
    }
}
