using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// Resend 邮件通道（生产实现）。
/// 发件域名需在 Resend 完成验证；API key 与发件地址经 compose 环境变量注入，
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

    public async Task SendPasswordResetNoticeAsync(string email, CancellationToken ct)
    {
        var (subject, html) = EmailTemplates.PasswordResetNotice();
        await SendCoreAsync(email, subject, html, ct);
        logger.LogInformation("密码重置通知已发送 email={Email}", MaskEmail(email));
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
            logger.LogError("Resend API 失败 status={Status} detail={Detail}", (int)response.StatusCode, SummarizeErrorBody(body));
            throw new InvalidOperationException($"Resend API 返回 {(int)response.StatusCode}");
        }
    }

    // 错误回包可能回显提交内容（收件地址、主题等）：只解析 name/message 并截断，不落完整 body。
    private static string SummarizeErrorBody(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var root = doc.RootElement;
                var name = root.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;
                var message = root.TryGetProperty("message", out var messageProp) ? messageProp.GetString() : null;
                var detail = string.IsNullOrWhiteSpace(message) ? name : $"{name}: {message}";
                if (!string.IsNullOrWhiteSpace(detail))
                {
                    return detail.Length <= 200 ? detail : detail[..200];
                }
            }
        }
        catch (JsonException)
        {
            // 非 JSON 回包按原文截断处理。
        }

        return body.Length <= 200 ? body : body[..200];
    }
}
