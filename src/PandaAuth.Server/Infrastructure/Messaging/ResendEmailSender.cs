using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// Resend 邮件通道（生产实现）。移植自 panda-asst-server（2026-09-19），改动仅命名空间与品牌。
/// 发件域名 pandalabs.cc 已在 Resend 账号验证；API key 与发件地址经 compose 环境变量注入，
/// 生产缺失即启动失败（见 Program.cs 的 ValidateOnStart）。
/// </summary>
public sealed class ResendEmailSender(
    HttpClient httpClient,
    IOptions<EmailOptions> options,
    ILogger<ResendEmailSender> logger) : IEmailSender
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    // PII 纪律：日志不落明文邮箱（站内 Email 本为明文存储，但日志会被聚合/留存得更久），只留定位所需的局部信息。
    private static string MaskEmail(string email)
    {
        var at = email.LastIndexOf('@');
        if (at <= 0)
        {
            return "***";
        }

        var local = email[..at];
        var head = local.Length <= 2 ? local : local[..2];
        return $"{head}***{email[at..]}";
    }

    public async Task SendVerificationCodeAsync(string email, string code, CancellationToken ct)
    {
        var (subject, html) = EmailTemplates.VerificationCode(code);
        await SendCoreAsync(email, subject, html, ct);
        logger.LogInformation("验证码邮件已发送 email={Email}", MaskEmail(email));
    }

    public async Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct)
    {
        await SendCoreAsync(email, subject, htmlBody, ct);
        logger.LogInformation("邮件已发送 email={Email} subject={Subject}", MaskEmail(email), subject);
    }

    private async Task SendCoreAsync(string email, string subject, string html, CancellationToken ct)
    {
        var payload = new
        {
            from = options.Value.FromAddress,
            to = new[] { email },
            subject,
            html,
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.resend.com/emails")
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, JsonOptions), Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.Value.ApiKey);

        using var response = await httpClient.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            logger.LogError("Resend API 失败 status={Status} body={Body}", (int)response.StatusCode, body);
            throw new InvalidOperationException($"Resend API 返回 {(int)response.StatusCode}");
        }
    }
}
