namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>邮件主题与 HTML 模板集中管理（模板与发送逻辑分离，便于后续迁模板引擎）。品牌对齐 IDP 登录页设计令牌。</summary>
public static class EmailTemplates
{
    public static (string Subject, string Html) EmailConfirmation(string token) =>
    (
        "确认你的 PandaAuth 邮箱",
        TokenMessage("确认邮箱", "你正在确认 PandaAuth 账号邮箱。", token)
    );

    public static (string Subject, string Html) EmailChange(string token) =>
    (
        "确认你的 PandaAuth 新邮箱",
        TokenMessage("确认新邮箱", "你正在将此邮箱设置为 PandaAuth 账号的新邮箱。", token)
    );

    public static (string Subject, string Html) PasswordReset(string token) =>
    (
        "重置你的 PandaAuth 密码",
        TokenMessage("重置密码", "你正在恢复 PandaAuth 账号。", token)
    );

    public static (string Subject, string Html) EmailChangeNotice() =>
    (
        "你的 PandaAuth 邮箱已更改",
        "<p>你的 PandaAuth 账号邮箱已更改。如果这不是你本人操作，请立即联系管理员。</p>"
    );

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

    private static string TokenMessage(string heading, string action, string token) =>
        $"""
        <h2 style="color:#2E6F96;margin-bottom:8px;">PandaAuth {heading}</h2>
        <p>{action}请输入以下一次性令牌：</p>
        <p style="font-size:18px;font-weight:bold;word-break:break-all;padding:16px;background:#f0f5f2;border-radius:8px;text-align:center;color:#2B3438;">{token}</p>
        <p>20 分钟内有效且只能使用一次。若非你本人操作，请忽略本邮件。</p>
        <p style="color:#6b6b70;font-size:14px;">此邮件由 PandaAuth 系统自动发送，请勿直接回复。</p>
        """;
}
