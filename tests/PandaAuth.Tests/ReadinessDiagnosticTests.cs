using System.Text.Json;
using System.Net;
using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ReadinessDiagnosticTests
{
    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task LoginFailureExposesOnlyStatus(HttpStatusCode status)
    {
        using var browser = new HttpClient(new LoginFailureHandler(status)) { BaseAddress = new Uri("https://localhost/") };
        using var actor = new ProtocolUser(new ProtocolActorSettings("test", "https://localhost/", "synthetic-sensitive-password",
            "client", "synthetic-sensitive-secret", "https://localhost/callback", "synthetic-sensitive-user", "login"),
            0, browser, new CookieContainer());
        var exception = await Assert.ThrowsAnyAsync<Exception>(() => actor.InitializeAsync(CancellationToken.None));
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(HarnessProgram.DescribeFailure(exception)));
        Assert.Equal((int)status, json.RootElement.GetProperty("loginStatus").GetInt32());
        Assert.DoesNotContain("synthetic-sensitive", json.RootElement.GetRawText());
    }

    private sealed class LoginFailureHandler(HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
                return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("synthetic-sensitive-response") });
            if (request.RequestUri!.AbsolutePath == "/account/login")
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                    "<input name=\"__RequestVerificationToken\" value=\"synthetic-sensitive-csrf\" />") });
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("/account/login", UriKind.Relative);
            return Task.FromResult(response);
        }
    }

    [Fact]
    public void RedirectDiagnosticsOnlyExposeBoundedCategories()
    {
        var exception = new SnapshotProtocolException(HttpStatusCode.Redirect, HttpStatusCode.Unauthorized,
            HttpStatusCode.BadRequest, false, "invalid_grant", new Uri("https://localhost:39001/"),
            new Uri("https://synthetic-sensitive.example/unknown?token=synthetic-sensitive-token"));
        var json = JsonSerializer.Serialize(HarnessProgram.DescribeFailure(exception));
        Assert.DoesNotContain("synthetic-sensitive", json);
        Assert.Contains("other", json);
        Assert.False(exception.RedirectOwnerMatches);
    }

    [Fact]
    public void FailureDiagnosticsNeverSerializeExceptionMessagesOrProviderData()
    {
        var exception = new InvalidOperationException("synthetic-sensitive-token-do-not-emit");
        exception.Data["ConnectionStrings:Default"] = "synthetic-sensitive-provider-do-not-emit";
        var json = JsonSerializer.Serialize(HarnessProgram.DescribeFailure(exception));
        Assert.DoesNotContain("synthetic-sensitive", json);
        Assert.Contains("InvalidOperationException", json);
    }
}
