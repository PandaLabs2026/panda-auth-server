using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Infrastructure.Messaging;
using Xunit;

namespace PandaAuth.Tests;

public sealed class NotifyEmailSenderTests
{
    [Fact]
    public async Task Sends_raw_transactional_payload_to_the_gateway()
    {
        HttpRequestMessage? captured = null;
        string? body = null;
        var tokenFile = Path.Combine(Path.GetTempPath(), $"notify-token-{Guid.NewGuid():N}");
        File.WriteAllText(tokenFile, "test-token");
        try
        {
            var options = new EmailOptions
            {
                Transport = "Notify",
                NotifyUrl = "https://notify.example",
                NotifyTenantId = "t0000",
                NotifyProducer = "panda-auth-server",
                NotifyTokenFile = tokenFile,
            };
            var handler = new StubHandler(request =>
            {
                captured = request;
                body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            });
            var sender = new NotifyEmailSender(
                new HttpClient(handler),
                Options.Create(options),
                NullLogger<NotifyEmailSender>.Instance);

            await sender.SendAsync("person@example.test", "Subject", "<p>Hello <strong>person</strong></p>", CancellationToken.None);

            Assert.NotNull(captured);
            Assert.Equal("https://notify.example/v1/messages/raw", captured!.RequestUri!.ToString());
            Assert.Equal("Bearer", captured.Headers.Authorization!.Scheme);
            Assert.Equal("test-token", captured.Headers.Authorization.Parameter);
            Assert.Equal("panda-auth-server", captured.Headers.GetValues("X-Notify-Producer").Single());
            using var document = JsonDocument.Parse(body!);
            var root = document.RootElement;
            Assert.Equal("t0000", root.GetProperty("tenantId").GetString());
            Assert.Equal("panda-auth", root.GetProperty("product").GetString());
            Assert.Equal("person@example.test", root.GetProperty("to").GetString());
            Assert.Equal("Subject", root.GetProperty("subject").GetString());
            Assert.Contains("Hello person", root.GetProperty("text").GetString()!);
            Assert.Contains("<strong>", root.GetProperty("html").GetString()!);
            Assert.StartsWith("auth:", root.GetProperty("idempotencyKey").GetString()!);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Fact]
    public async Task Non_success_gateway_response_fails_the_send()
    {
        var tokenFile = Path.Combine(Path.GetTempPath(), $"notify-token-{Guid.NewGuid():N}");
        File.WriteAllText(tokenFile, "test-token");
        try
        {
            var options = new EmailOptions
            {
                NotifyUrl = "https://notify.example",
                NotifyTenantId = "t0000",
                NotifyTokenFile = tokenFile,
            };
            var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
            var sender = new NotifyEmailSender(
                new HttpClient(handler),
                Options.Create(options),
                NullLogger<NotifyEmailSender>.Instance);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                sender.SendAsync("person@example.test", "Subject", "<p>Body</p>", CancellationToken.None));
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Fact]
    public async Task Fails_over_to_the_next_endpoint_on_5xx_with_the_same_idempotency_key()
    {
        var tokenFile = Path.Combine(Path.GetTempPath(), $"notify-token-{Guid.NewGuid():N}");
        File.WriteAllText(tokenFile, "test-token");
        var requests = new List<(string Host, string Key)>();
        try
        {
            var options = new EmailOptions
            {
                NotifyUrls = "https://primary.example, https://standby.example",
                NotifyTenantId = "t0000",
                NotifyTokenFile = tokenFile,
            };
            var handler = new StubHandler(request =>
            {
                var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                using var document = JsonDocument.Parse(body);
                requests.Add((request.RequestUri!.Host, document.RootElement.GetProperty("idempotencyKey").GetString()!));
                return request.RequestUri!.Host == "primary.example"
                    ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                    : new HttpResponseMessage(HttpStatusCode.Accepted);
            });
            var sender = new NotifyEmailSender(
                new HttpClient(handler),
                Options.Create(options),
                NullLogger<NotifyEmailSender>.Instance);

            await sender.SendAsync("person@example.test", "Subject", "<p>Body</p>", CancellationToken.None);

            Assert.Equal(2, requests.Count);
            Assert.Equal("primary.example", requests[0].Host);
            Assert.Equal("standby.example", requests[1].Host);
            Assert.Equal(requests[0].Key, requests[1].Key);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Fact]
    public async Task Does_not_fail_over_on_a_client_error()
    {
        var tokenFile = Path.Combine(Path.GetTempPath(), $"notify-token-{Guid.NewGuid():N}");
        File.WriteAllText(tokenFile, "test-token");
        var requests = 0;
        try
        {
            var options = new EmailOptions
            {
                NotifyUrls = "https://primary.example,https://standby.example",
                NotifyTenantId = "t0000",
                NotifyTokenFile = tokenFile,
            };
            var handler = new StubHandler(_ =>
            {
                requests++;
                return new HttpResponseMessage(HttpStatusCode.BadRequest);
            });
            var sender = new NotifyEmailSender(
                new HttpClient(handler),
                Options.Create(options),
                NullLogger<NotifyEmailSender>.Instance);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                sender.SendAsync("person@example.test", "Subject", "<p>Body</p>", CancellationToken.None));

            Assert.Equal(1, requests);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Fact]
    public async Task Password_reset_notice_uses_the_template_endpoint()
    {
        HttpRequestMessage? captured = null;
        string? body = null;
        var tokenFile = Path.Combine(Path.GetTempPath(), $"notify-token-{Guid.NewGuid():N}");
        File.WriteAllText(tokenFile, "test-token");
        try
        {
            var options = new EmailOptions
            {
                NotifyUrl = "https://notify.example",
                NotifyTenantId = "t0000",
                NotifyTokenFile = tokenFile,
            };
            var handler = new StubHandler(request =>
            {
                captured = request;
                body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            });
            var sender = new NotifyEmailSender(
                new HttpClient(handler),
                Options.Create(options),
                NullLogger<NotifyEmailSender>.Instance);

            await sender.SendPasswordResetNoticeAsync("person@example.test", CancellationToken.None);

            Assert.NotNull(captured);
            Assert.Equal("https://notify.example/v1/messages", captured!.RequestUri!.ToString());
            using var document = JsonDocument.Parse(body!);
            var root = document.RootElement;
            Assert.Equal("panda-auth", root.GetProperty("product").GetString());
            Assert.Equal("t0000", root.GetProperty("tenantId").GetString());
            Assert.Equal("password-reset-notice", root.GetProperty("templateKey").GetString());
            Assert.Equal("zh-CN", root.GetProperty("locale").GetString());
            Assert.Empty(root.GetProperty("variables").EnumerateObject());
            Assert.StartsWith("auth:", root.GetProperty("idempotencyKey").GetString()!);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(handler(request));
    }
}
