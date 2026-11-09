using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Infrastructure.Messaging;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ProfileContactMailTests
{
    private sealed class CaptureLog<T> : ILogger<T>
    {
        public List<string> Lines { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> format)
            => Lines.Add(format(state, error));
    }
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request);
    }

    [Fact]
    public async Task Notify_uses_contact_template_and_persistent_delivery_identity_without_contact_values_in_logs()
    {
        var tokenFile = Path.Combine(Path.GetTempPath(), "profile-notify-" + Guid.NewGuid().ToString("N"));
        await File.WriteAllTextAsync(tokenFile, "synthetic-only");
        try
        {
            var bodies = new List<JsonElement>(); var logs = new CaptureLog<NotifyEmailSender>();
            using var http = new HttpClient(new Handler(async request =>
            {
                Assert.Equal("/v1/messages", request.RequestUri!.AbsolutePath);
                using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
                bodies.Add(json.RootElement.Clone());
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            }));
            IEmailSender sender = new NotifyEmailSender(http, Options.Create(new EmailOptions
            {
                NotifyUrl = "https://synthetic.invalid", NotifyTenantId = "fixture", NotifyTokenFile = tokenFile,
            }), logs);
            var delivery = Guid.NewGuid();
            await sender.SendProfileContactVerificationAsync("private-contact@example.invalid", "private-proof", delivery, default);
            await sender.SendProfileContactVerificationAsync("private-contact@example.invalid", "private-proof", delivery, default);
            await sender.SendProfileContactVerificationAsync("private-contact@example.invalid", "different-proof", Guid.NewGuid(), default);
            Assert.All(bodies, body => Assert.Equal("profile-contact-verification", body.GetProperty("templateKey").GetString()));
            Assert.Equal("private-proof", bodies[0].GetProperty("variables").GetProperty("token").GetString());
            Assert.Equal(bodies[0].GetProperty("idempotencyKey").GetString(), bodies[1].GetProperty("idempotencyKey").GetString());
            Assert.NotEqual(bodies[0].GetProperty("idempotencyKey").GetString(), bodies[2].GetProperty("idempotencyKey").GetString());
            Assert.DoesNotContain(logs.Lines, line => line.Contains("example.invalid") || line.Contains("private-proof"));
        }
        finally { File.Delete(tokenFile); }
    }

    [Fact]
    public async Task Resend_fallback_uses_the_delivery_identity_and_does_not_log_provider_echoes()
    {
        var keys = new List<string>(); var logs = new CaptureLog<ResendEmailSender>();
        using var http = new HttpClient(new Handler(request =>
        {
            keys.Add(request.Headers.GetValues("Idempotency-Key").Single());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
            { Content = new StringContent("{\"message\":\"private-contact@example.invalid private-proof\"}") });
        }));
        IEmailSender sender = new ResendEmailSender(http, Options.Create(new EmailOptions
            { ApiKey = "synthetic-only", FromAddress = "synthetic@example.invalid" }), logs);
        var delivery = Guid.NewGuid();
        for (var i = 0; i < 2; i++)
            await Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendProfileContactVerificationAsync(
                "private-contact@example.invalid", "private-proof", delivery, default));
        Assert.Equal(keys[0], keys[1]);
        Assert.DoesNotContain(logs.Lines, line => line.Contains("example.invalid") || line.Contains("private-proof"));
    }
}
