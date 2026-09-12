namespace PandaAuth.Server.Domain;

/// <summary>登录审计日志：记录 IP、设备、时间、结果与客户端 App。</summary>
public class LoginLog
{
    public long Id { get; set; }

    public string? UserId { get; set; }

    public string UserName { get; set; } = string.Empty;

    public string? ClientId { get; set; }

    public string? IpAddress { get; set; }

    public string? UserAgent { get; set; }

    public bool Succeeded { get; set; }

    public string? FailureReason { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
