namespace PandaAuth.Server.Domain;

/// <summary>
/// 通知中心已读水位：每管理员一行，LastAuditId 及以下的审计条目视为已读。
/// 一期通知源=管理审计流（admin_audit_logs，只记变更不记读），本表只存「读到哪了」，
/// 不复制通知内容——通知是审计的呈现形态（share 契约 AdminNotificationEntry 与
/// AdminAuditLogEntry 字段严格对齐）。游标单调不回退（控制器校验）。
/// </summary>
public class AdminNotificationCursor
{
    /// <summary>管理员用户 Id（Access Token 的 sub）；每管理员至多一行。</summary>
    public string AdminUserId { get; set; } = string.Empty;

    /// <summary>已读水位：admin_audit_logs.Id，≤ 该值视为已读。</summary>
    public long LastAuditId { get; set; }

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
