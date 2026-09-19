using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Features.Account;

public enum OtpVerifyOutcome
{
    Success,
    InvalidCode,
    Locked,
    MissingOrExpired,
}

/// <summary>邮箱验证码频控超限（区分于验证失败，调用方给中性文案）。</summary>
public sealed class OtpRateLimitedException : Exception;

/// <summary>
/// 邮箱验证码服务：签发与校验。移植自 panda-asst-server 的 OtpService，口径不变：
/// 6 位 CSPRNG、TTL 5 分钟、频控 1 次/分钟 + 5 次/小时（按邮箱哈希）、
/// 5 次失败锁定 15 分钟、成功即消费、验证码以 SHA256 哈希入库。
/// </summary>
/// <remarks>
/// 与 asst 的关键差异——<see cref="IssueAsync"/> 只签发不发送：发送与否由调用方按
/// 「账号是否存在」决定（防枚举），而签发路径（计数 + 写库）对存在/不存在的邮箱**完全一致**，
/// 消除忘记密码入口的时序侧信道。为不存在的邮箱写入的哈希行有 TTL 与保留清理兜底。
/// </remarks>
public sealed class OtpService(
    PandaAuthDbContext db,
    TimeProvider timeProvider)
{
    public const int CodeLength = 6;
    public const int CodeTtlMinutes = 5;
    public const int MaxFailures = 5;
    public const int LockMinutes = 15;

    /// <summary>
    /// 签发验证码（入库哈希，返回明文给调用方决定是否发送）。频控超限抛
    /// <see cref="OtpRateLimitedException"/>——无论账号是否存在都先走同一套计数与写入。
    /// </summary>
    public async Task<string> IssueAsync(string email, CancellationToken ct)
    {
        var emailHash = VerificationHasher.EmailHash(email);
        var now = timeProvider.GetUtcNow();

        var lastMinute = await db.VerificationCodes
            .CountAsync(v => v.EmailHash == emailHash && v.CreatedAt > now.AddMinutes(-1), ct);
        if (lastMinute >= 1)
        {
            throw new OtpRateLimitedException();
        }

        var lastHour = await db.VerificationCodes
            .CountAsync(v => v.EmailHash == emailHash && v.CreatedAt > now.AddHours(-1), ct);
        if (lastHour >= 5)
        {
            throw new OtpRateLimitedException();
        }

        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        db.VerificationCodes.Add(new VerificationCode
        {
            Id = Guid.NewGuid(),
            EmailHash = emailHash,
            CodeHash = VerificationHasher.CodeHash(code),
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(CodeTtlMinutes),
        });
        await db.SaveChangesAsync(ct);
        return code;
    }

    /// <summary>校验验证码：取该邮箱最近一条未消费记录比对；失败计数、锁定与消费语义同 asst。</summary>
    public async Task<OtpVerifyOutcome> VerifyAsync(string email, string code, CancellationToken ct)
    {
        var emailHash = VerificationHasher.EmailHash(email);
        var now = timeProvider.GetUtcNow();

        var candidate = await db.VerificationCodes
            .Where(v => v.EmailHash == emailHash && v.ConsumedAt == null)
            .OrderByDescending(v => v.CreatedAt)
            .FirstOrDefaultAsync(ct);

        if (candidate is null || candidate.ExpiresAt <= now)
        {
            return OtpVerifyOutcome.MissingOrExpired;
        }

        var recentFailures = await db.VerificationCodes
            .Where(v => v.EmailHash == emailHash && v.CreatedAt > now.AddMinutes(-LockMinutes))
            .SumAsync(v => v.FailedAttempts, ct);
        if (recentFailures >= MaxFailures)
        {
            return OtpVerifyOutcome.Locked;
        }

        if (candidate.CodeHash != VerificationHasher.CodeHash(code))
        {
            candidate.FailedAttempts++;
            await db.SaveChangesAsync(ct);
            return OtpVerifyOutcome.InvalidCode;
        }

        candidate.ConsumedAt = now;
        await db.SaveChangesAsync(ct);
        return OtpVerifyOutcome.Success;
    }
}
