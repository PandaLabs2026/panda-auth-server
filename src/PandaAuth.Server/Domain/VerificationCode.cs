namespace PandaAuth.Server.Domain;

/// <summary>
/// 邮箱验证码记录（忘记密码自助重置）。移植自 panda-asst-server，表结构照搬。
/// 邮箱与验证码均以 SHA256 哈希入库（键可检索、明文不落库）；TTL 5 分钟；
/// 5 次失败锁定 15 分钟；成功即消费。
/// </summary>
public class VerificationCode
{
    public Guid Id { get; set; }

    /// <summary>邮箱哈希（VerificationHasher.EmailHash）：频控与检索键。</summary>
    public required string EmailHash { get; set; }

    /// <summary>验证码哈希（VerificationHasher.CodeHash）。</summary>
    public required string CodeHash { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>成功消费时间；null 表示未使用。</summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>本邮箱在锁定窗口内的累计验证失败次数（跨记录累计，见 OtpService.VerifyAsync）。</summary>
    public int FailedAttempts { get; set; }
}
