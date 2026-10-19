namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// 邮件发送抽象：通用业务邮件 + 密码重置安全通知（通知属安全语义，单列方法便于实现侧
/// 统一加日志/脱敏口径）。实现按环境切换（生产 ResendEmailSender / 开发 DevEmailSender）。
/// </summary>
public interface IEmailSender
{
    Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct);

    /// <summary>密码重置成功后的安全通知：收件人是账号持有人，内容见 EmailTemplates.PasswordResetNotice。</summary>
    Task SendPasswordResetNoticeAsync(string email, CancellationToken ct);

    Task SendEmailConfirmationAsync(string email, string token, CancellationToken ct)
    {
        var (subject, html) = EmailTemplates.EmailConfirmation(token);
        return SendAsync(email, subject, html, ct);
    }

    Task SendEmailChangeConfirmationAsync(string email, string token, CancellationToken ct)
    {
        var (subject, html) = EmailTemplates.EmailChange(token);
        return SendAsync(email, subject, html, ct);
    }

    Task SendPasswordResetTokenAsync(string email, string token, CancellationToken ct)
    {
        var (subject, html) = EmailTemplates.PasswordReset(token);
        return SendAsync(email, subject, html, ct);
    }

    Task SendEmailChangeNoticeAsync(string email, CancellationToken ct)
    {
        var (subject, html) = EmailTemplates.EmailChangeNotice();
        return SendAsync(email, subject, html, ct);
    }
}
