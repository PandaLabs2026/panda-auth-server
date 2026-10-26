namespace PandaAuth.Server.Domain;

/// <summary>
/// MFA 一次性服务端状态：原 WebAuthn ceremony 载荷，现为操作授权行（op-grant:*，AUTH-DELIVERY-002）。
/// 默认 5 分钟过期、单次消费；消费用条件 UPDATE 原子完成（多实例安全），过期行由保留任务回收。
/// </summary>
public sealed class MfaChallenge
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Purpose { get; set; }
    public required string SubjectId { get; set; }
    public required byte[] Value { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
