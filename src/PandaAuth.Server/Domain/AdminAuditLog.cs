namespace PandaAuth.Server.Domain;

/// <summary>
/// 管理操作审计日志：谁（actor）在何时对什么目标（target）做了哪类管理变更（action）。
/// 动作名契约见 share 的 <c>AdminAuditAction</c>（user.freeze / client.rotate_secret 等）。
/// 只审计变更，不审计读——读的量级会把审计表变成访问日志。
/// </summary>
public class AdminAuditLog
{
    public long Id { get; set; }

    /// <summary>操作者（Access Token 的 sub）。</summary>
    public string ActorUserId { get; set; } = string.Empty;

    /// <summary>操作者用户名（冗余存储，账号事后改名/删除时审计仍可读）。</summary>
    public string? ActorUserName { get; set; }

    /// <summary>动作名（AdminAuditAction 常量）。</summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>目标类型（"user" / "client"）。</summary>
    public string? TargetType { get; set; }

    /// <summary>目标标识（用户 Id 或 clientId）。密钥等敏感值绝不入审计。</summary>
    public string? TargetId { get; set; }

    /// <summary>动作细节 JSON（如变更前后状态、用户名）；不含任何凭据。</summary>
    public string? Detail { get; set; }

    public string? IpAddress { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
