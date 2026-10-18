namespace PandaAuth.Server.Domain;

/// <summary>管理员 MFA 恢复的独立审计事实；不得包含任何凭据或 ceremony 原文。</summary>
public sealed class MfaRecoveryEvent
{
    /// <summary>管理员重置 MFA 的事件原因；恢复策略据此区分“管理员重置”与普通因子操作。</summary>
    public const string AdminResetReason = "admin_reset";

    public long Id { get; set; }
    public string ActorUserId { get; set; } = string.Empty;
    public string TargetUserId { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public string AuthenticationMethod { get; set; } = string.Empty;
    public string? RequestId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
