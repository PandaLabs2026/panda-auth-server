namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>邮件主题与 HTML 模板集中管理（模板与发送逻辑分离，便于后续迁模板引擎）。品牌对齐 IDP 登录页设计令牌。</summary>
public static class EmailTemplates
{
    /// <summary>验证码邮件。有效期口径与 OtpService.CodeTtlMinutes 一致，改动须同步。</summary>
    public static (string Subject, string Html) VerificationCode(string code) =>
    (
        "PandaAuth 验证码",
        $"""
        <h2 style="color:#2E6F96;margin-bottom:8px;">PandaAuth 验证码</h2>
        <p>你正在重置密码，验证码为：</p>
        <p style="font-size:28px;font-weight:bold;letter-spacing:4px;padding:16px;background:#f0f5f2;border-radius:8px;text-align:center;color:#2B3438;">{code}</p>
        <p>5 分钟内有效。若非你本人操作，请忽略本邮件（可能是他人误填了你的邮箱）。</p>
        <p style="color:#6b6b70;font-size:14px;">此邮件由 PandaAuth 系统自动发送，请勿直接回复。</p>
        """
    );

    /// <summary>密码重置成功通知（重置完成后发送，提示凭据已变更）。</summary>
    public static (string Subject, string Html) PasswordResetNotice() =>
    (
        "PandaAuth 密码已重置",
        """
        <h2 style="color:#2E6F96;margin-bottom:8px;">你的 PandaAuth 密码已重置</h2>
        <p>密码刚刚通过邮箱验证码完成重置，所有旧的登录会话已被强制下线。</p>
        <p>若非你本人操作，请立即使用「忘记密码」重新接管账号，并联系管理员。</p>
        <p style="color:#6b6b70;font-size:14px;">此邮件由 PandaAuth 系统自动发送，请勿直接回复。</p>
        """
    );
}
