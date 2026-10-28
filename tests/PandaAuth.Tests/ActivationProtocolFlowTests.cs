using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using PandaAuth.ReadinessHarness;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ActivationProtocolFlowTests
{
    [Theory]
    [InlineData("admin")]
    [InlineData("me")]
    public async Task FreshMfaLoginCanAcceptOneBffWithoutStartingTheOther(string component)
    {
        var handler = new MfaHandler(component);
        using var browser = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:39001/") };
        var waits = 0;
        var subject = await BffLogin.LoginAsync(browser, component, "approved-fixture", "fixture-password", new byte[20],
            waitForStep: _ => { waits++; return Task.CompletedTask; });
        Assert.Equal("approved-subject", subject);
        Assert.Equal(1, waits);
        Assert.True(handler.MfaPosted);
        Assert.DoesNotContain(handler.Paths, path => path.StartsWith(component == "admin" ? "/me/" : "/admin/"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallbackStateOrOwnerMismatchPreventsClientSecretExchange(bool foreign)
    {
        var handler = new SsoHandler(foreign ? "foreign" : "wrong-state");
        using var browser = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:39001/") };
        using var actor = Actor(browser);
        await Assert.ThrowsAsync<InvalidOperationException>(() => actor.AuthorizeSsoAsync(CancellationToken.None));
        Assert.Equal(0, handler.TokenPosts);
    }

    [Fact]
    public async Task ExistingApprovedSsoUsesPkceAndRotatesTokensWithoutAnotherPassword()
    {
        var handler = new SsoHandler("valid");
        using var browser = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:39001/") };
        using (var actor = Actor(browser))
        {
            await actor.AuthorizeSsoAsync(CancellationToken.None);
            Assert.Equal("fixture-access", actor.Snapshot().AccessToken);
            Assert.Equal("fixture-refresh", actor.Snapshot().RefreshToken);
        }
        Assert.Equal(1, handler.TokenPosts);
        // The protocol actor borrows this BFF browser; disposing it must not
        // dispose the caller's session before its logout/revocation checks.
        using var alive = await browser.GetAsync("/still-owned");
        Assert.Equal(HttpStatusCode.OK, alive.StatusCode);
    }

    [Fact]
    public async Task FreshCodeExchangeUsesTheSameRequiredMfaFlow()
    {
        var handler = new MfaHandler("admin", directOAuth: true);
        using var browser = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:39001/") };
        var settings = new ProtocolActorSettings(new string('a', 32), browser.BaseAddress.AbsoluteUri, "fixture-password",
            "admin-web", "fixture-client-secret", "https://localhost:39001/callback", "approved-fixture", "cookie");
        using var actor = new ProtocolUser(settings, 0, browser, new CookieContainer(), new byte[20], _ => Task.CompletedTask);
        await actor.InitializeAsync(CancellationToken.None);
        Assert.True(handler.MfaPosted);
        Assert.Equal("fixture-access", actor.Snapshot().AccessToken);
    }

    private static ProtocolUser Actor(HttpClient browser) => new(new ProtocolActorSettings(new string('a', 32),
        browser.BaseAddress!.AbsoluteUri, "fixture-password", "admin-web", "fixture-client-secret",
        "https://localhost:39001/callback", "approved-fixture", "cookie", "openid profile roles offline_access auth.admin"),
        0, browser, new CookieContainer());

    private sealed class SsoHandler(string mode) : HttpMessageHandler
    {
        public int TokenPosts { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == PandaAuthEndpoints.Authorization)
            {
                var query = QueryHelpers.ParseQuery(request.RequestUri.Query);
                Assert.Equal("S256", query["code_challenge_method"].ToString());
                Assert.Contains("auth.admin", query["scope"].ToString());
                var state = mode == "wrong-state" ? "different-state" : query["state"].ToString();
                return Redirect((mode == "foreign" ? "https://outside.invalid" : "https://localhost:39001") +
                    "/callback?code=fixture-code&state=" + state);
            }
            if (request.RequestUri.AbsolutePath == PandaAuthEndpoints.Token)
            {
                TokenPosts++;
                Assert.Contains("code_verifier=", await request.Content!.ReadAsStringAsync(cancellationToken));
                return new(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"fixture-access\",\"refresh_token\":\"fixture-refresh\",\"expires_in\":600}") };
            }
            return new(HttpStatusCode.OK);
        }
    }

    private sealed class MfaHandler(string component, bool directOAuth = false) : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];
        public bool MfaPosted { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            Paths.Add(path);
            if (directOAuth && path == PandaAuthEndpoints.Authorization)
            {
                if (!MfaPosted) return Redirect("/account/login");
                var query = QueryHelpers.ParseQuery(request.RequestUri.Query);
                return Redirect("https://localhost:39001/callback?code=fixture-code&state=" + query["state"]);
            }
            if (directOAuth && path == PandaAuthEndpoints.Token)
                return new(HttpStatusCode.OK) { Content = new StringContent("{\"access_token\":\"fixture-access\",\"refresh_token\":\"fixture-refresh\",\"expires_in\":600}") };
            if (path == "/admin/challenge" || path == "/me/login")
                return Redirect("/account/login?returnUrl=%2Fconnect%2Fauthorize");
            if (path == "/account/login" && request.Method == HttpMethod.Post)
                return Redirect("/account/mfa/challenge");
            if (path == "/account/mfa/challenge/totp")
            {
                var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken));
                Assert.Matches("^[0-9]{6}$", form["Code"].ToString());
                MfaPosted = true;
                return Redirect(PandaAuthEndpoints.Authorization);
            }
            if (path == PandaAuthEndpoints.Authorization) return Redirect("/" + component + "/");
            if (path == "/" + component + "/api/session")
                return new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(new
                    { subject = "approved-subject", roles = component == "admin" ? new[] { "admin" } : [] })) };
            return new(HttpStatusCode.OK) { Content = new StringContent("<input name=\"__RequestVerificationToken\" value=\"fixture-csrf\"/>") };
        }
    }

    private static HttpResponseMessage Redirect(string path) => new(HttpStatusCode.Redirect)
        { Headers = { Location = new Uri(path, UriKind.RelativeOrAbsolute) } };
}
