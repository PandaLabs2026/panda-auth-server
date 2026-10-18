using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// P1 transport-first sender: products keep their current templates and call the
/// shared notification gateway for durable outbox/retry/audit. Direct Resend remains
/// available with Email:Transport=Resend as the break-glass path.
/// </summary>
public sealed class NotifyEmailSender : IEmailSender
{
    private static readonly Regex Tags = new("<[^>]+>", RegexOptions.Compiled);
    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.Compiled);
    private readonly HttpClient _http;
    private readonly EmailOptions _options;
    private readonly ILogger<NotifyEmailSender> _logger;
    private readonly string? _token;

    public NotifyEmailSender(HttpClient http, IOptions<EmailOptions> options, ILogger<NotifyEmailSender> logger)
    {
        _http = http;
        _options = options.Value;
        _logger = logger;
        if (!string.IsNullOrWhiteSpace(_options.NotifyTokenFile))
        {
            if (!File.Exists(_options.NotifyTokenFile))
            {
                throw new FileNotFoundException("Email:NotifyTokenFile was not found.", _options.NotifyTokenFile);
            }

            _token = File.ReadAllText(_options.NotifyTokenFile).Trim();
        }

        if (string.IsNullOrWhiteSpace(_token) && string.IsNullOrWhiteSpace(_options.NotifyClientCertificateFile))
        {
            throw new InvalidOperationException("Notify transport requires NotifyTokenFile or NotifyClientCertificateFile.");
        }
    }

    public async Task SendPasswordResetNoticeAsync(string email, CancellationToken ct)
    {
        var (subject, html) = EmailTemplates.PasswordResetNotice();
        await SendAsync(email, subject, html, ct);
    }

    public async Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct)
    {
        var payload = new
        {
            tenantId = _options.NotifyTenantId,
            product = "panda-auth",
            to = email,
            subject,
            text = ToPlainText(htmlBody),
            html = htmlBody,
            idempotencyKey = BuildIdempotencyKey(email, subject, htmlBody),
        };

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(new Uri(_options.NotifyUrl.TrimEnd('/') + "/"), "v1/messages/raw"))
        {
            Content = JsonContent.Create(payload),
        };
        if (!string.IsNullOrWhiteSpace(_token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        }

        if (!string.IsNullOrWhiteSpace(_options.NotifyProducer))
        {
            request.Headers.Add("X-Notify-Producer", _options.NotifyProducer);
        }

        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError(
                "Notify transactional delivery failed email={Email} status={Status}",
                MaskEmail(email),
                (int)response.StatusCode);
            throw new InvalidOperationException($"Notify API returned {(int)response.StatusCode}.");
        }

        _logger.LogInformation("Notify transactional delivery accepted email={Email} subject={Subject}", MaskEmail(email), subject);
    }

    private static string BuildIdempotencyKey(string email, string subject, string html)
    {
        var bucket = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmm", System.Globalization.CultureInfo.InvariantCulture);
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{email}|{subject}|{html}|{bucket}")));
        return $"auth:{hash}";
    }

    private static string ToPlainText(string html)
    {
        var text = Tags.Replace(html, " ");
        text = WebUtility.HtmlDecode(text);
        return Whitespace.Replace(text, " ").Trim();
    }

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
}
