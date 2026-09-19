namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// 邮件发送抽象：验证码专用 + 通用业务邮件两方法（分离的理由见 asst ADR 0012：验证码与业务推送不共享实现）。
/// 实现按环境切换（生产 ResendEmailSender / 开发 DevEmailSender），注册见 Program.cs。
/// 移植自 panda-asst-server（2026-09-19）。
/// </summary>
public interface IEmailSender
{
    Task SendVerificationCodeAsync(string email, string code, CancellationToken ct);

    Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct);
}
