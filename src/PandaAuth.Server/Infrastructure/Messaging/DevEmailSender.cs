namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// 开发环境邮件通道：验证码落 warning 日志、不外发（零外部依赖、不打扰真实邮箱）。
/// 生产环境注册 ResendEmailSender（见 Program.cs 的环境分支）。
/// </summary>
public sealed class DevEmailSender(ILogger<DevEmailSender> logger) : IEmailSender
{
    public Task SendVerificationCodeAsync(string email, string code, CancellationToken ct)
    {
        logger.LogWarning("[DevEmail] 验证码投递（仅限非生产环境）email={Email} code={Code}", email, code);
        return Task.CompletedTask;
    }

    public Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct)
    {
        logger.LogWarning("[DevEmail] 邮件投递（仅限非生产环境）email={Email} subject={Subject}", email, subject);
        return Task.CompletedTask;
    }
}
