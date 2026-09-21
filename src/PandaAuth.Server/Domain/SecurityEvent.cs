namespace PandaAuth.Server.Domain;

/// <summary>
/// 不可变安全事件：记录身份、MFA、会话、权限和外部身份变更的可追溯上下文。
/// 凭据、Token 原文和 Passkey 私钥等敏感值不得写入 Metadata。
/// </summary>
public sealed class SecurityEvent
{
    public long Id { get; set; }

    public string? UserId { get; set; }

    public string? ActorUserId { get; set; }

    public string EventType { get; set; } = string.Empty;

    public string? TargetType { get; set; }

    public string? TargetId { get; set; }

    public string? AuthenticationMethod { get; set; }

    public string? Metadata { get; set; }

    public string? IpAddress { get; set; }

    public string? UserAgent { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public string? CorrelationId { get; set; }
}
