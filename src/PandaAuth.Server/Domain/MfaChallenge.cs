namespace PandaAuth.Server.Domain;

/// <summary>
/// WebAuthn ceremony 的服务端一次性状态（完整 options JSON，等价于 OpenIddict 自存的授权码载荷）。
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
