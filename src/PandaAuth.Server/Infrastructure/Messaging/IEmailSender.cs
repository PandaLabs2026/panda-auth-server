namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// 邮件发送抽象：验证码专用 + 通用业务邮件两方法（验证码与业务推送不共享实现）。
/// 实现按环境切换（生产 ResendEmailSender / 开发 DevEmailSender），注册见 Program.cs。
/// </summary>
public interface IEmailSender
{
    Task SendVerificationCodeAsync(string email, string code, CancellationToken ct);

    Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct);
}
