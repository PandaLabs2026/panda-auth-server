using System.Net;
using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class BffLoginTests
{
    [Fact]
    public async Task PasswordSuccessCannotBypassTheRequiredMfaChallenge()
    {
        using var browser = new HttpClient(new MfaBypassHandler()) { BaseAddress = new Uri("https://localhost:39001/") };
        var settings = new LoadRequest { RunId = new string('a', 32), BaseUri = browser.BaseAddress.AbsoluteUri,
            RootCertificateFile = "/fixture/root.pem", Password = "synthetic-only", ClientSecret = "synthetic-only",
            Workload = "cookie", Concurrency = 1, DurationSeconds = 3, RecoveryScenario = true,
            RecoveryTotpKey = Convert.ToBase64String(new byte[32]) };
        await Assert.ThrowsAsync<InvalidOperationException>(() => BffLogin.VerifyAsync(settings, browser));
    }

    private sealed class MfaBypassHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/account/login" && request.Method == HttpMethod.Get)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent("<input name=\"__RequestVerificationToken\" value=\"synthetic-csrf\"/>") });
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri(request.Method == HttpMethod.Post ? "/connect/authorize" :
                "/account/login?returnUrl=%2Fconnect%2Fauthorize", UriKind.Relative);
            return Task.FromResult(response);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InitialChallengeCannotSkipLoginOrEscapeTheFixture(bool external)
    {
        var handler = new ChallengeHandler(external);
        using var browser = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:39001/") };
        var settings = new LoadRequest { RunId = new string('a', 32), BaseUri = browser.BaseAddress.AbsoluteUri,
            RootCertificateFile = "/fixture/root.pem", Password = "synthetic-only", ClientSecret = "synthetic-only",
            Workload = "cookie", Concurrency = 1, DurationSeconds = 3, RecoveryScenario = true,
            RecoveryTotpKey = Convert.ToBase64String(new byte[32]) };
        await Assert.ThrowsAsync<InvalidOperationException>(() => BffLogin.VerifyAsync(settings, browser));
        Assert.Equal(0, handler.Posts);
    }

    private sealed class ChallengeHandler(bool external) : HttpMessageHandler
    {
        public int Posts { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post) Posts++;
            var response = new HttpResponseMessage(external ? HttpStatusCode.Redirect : HttpStatusCode.OK);
            if (external) response.Headers.Location = new Uri("https://outside.invalid/account/login");
            return Task.FromResult(response);
        }
    }
}
