using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using PandaAuth.Shared;

namespace PandaAuth.ReadinessHarness;

internal interface IProtocolActor : IDisposable
{
    Task InitializeAsync(CancellationToken cancellation);
    Task<HttpStatusCode> StepAsync(CancellationToken cancellation);
}

internal sealed record ProtocolActorSettings(string RunId,string BaseUri,string Password,string ClientId,string ClientSecret,
    string RedirectUri,string UserName,string Workload,string Scopes="openid profile offline_access");

internal sealed class ProtocolUser : IProtocolActor
{
    private readonly ProtocolActorSettings settings;
    private readonly int index;
    private readonly X509Certificate2? root;
    private readonly bool ownsBrowser = true;
    private readonly byte[]? totpSecret;
    private readonly Func<CancellationToken, Task>? waitForMfaStep;
    private CookieContainer cookies = new();
    private HttpClient browser;
    private string accessToken = "";
    private string refreshToken = "";
    private DateTimeOffset refreshAt;

    internal ProtocolUser(LoadRequest settings, int index, X509Certificate2 root)
        : this(new ProtocolActorSettings(settings.RunId,settings.BaseUri,settings.Password,settings.ClientId,settings.ClientSecret,
            settings.RedirectUri,settings.UserName(index),settings.Workload),index,root) { }

    internal ProtocolUser(ProtocolActorSettings settings, int index, X509Certificate2 root)
    {
        this.settings = settings; this.index = index; this.root = root;
        browser = CreateBrowser(new Uri(settings.BaseUri), root, cookies);
    }

    internal ProtocolUser(ProtocolActorSettings settings, int index, HttpClient browser, CookieContainer cookies,
        byte[]? totpSecret = null, Func<CancellationToken, Task>? waitForMfaStep = null)
    {
        Require(browser.BaseAddress?.AbsoluteUri == settings.BaseUri);
        this.settings = settings; this.index = index; this.browser = browser; this.cookies = cookies;
        this.totpSecret = totpSecret; this.waitForMfaStep = waitForMfaStep; ownsBrowser = false;
    }

    internal static HttpClient CreateBrowser(LoadRequest settings, X509Certificate2 root, CookieContainer? cookies = null)
        => CreateBrowser(new Uri(settings.BaseUri),root,cookies);

    internal static HttpClient CreateBrowser(Uri owner, X509Certificate2? root, CookieContainer? cookies = null)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false, CookieContainer = cookies ?? new CookieContainer(), UseProxy = false };
        if (root is not null) handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
        {
            if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0)
                return false;
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(certificate);
        };
        return new HttpClient(handler) { BaseAddress = owner, Timeout = TimeSpan.FromSeconds(15) };
    }

    public async Task InitializeAsync(CancellationToken cancellation) => await LoginAsync(cancellation);

    public async Task<HttpStatusCode> StepAsync(CancellationToken cancellation)
    {
        if (settings.Workload == "bearer" && DateTimeOffset.UtcNow >= refreshAt)
        {
            var renewed = await ExchangeAsync(new()
            {
                ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken,
                ["client_id"] = settings.ClientId, ["client_secret"] = settings.ClientSecret
            }, cancellation);
            if (renewed != HttpStatusCode.OK) return renewed;
        }
        if (settings.Workload == "login")
        {
            Require(ownsBrowser);
            browser.Dispose();
            cookies = new CookieContainer();
            browser = CreateBrowser(new Uri(settings.BaseUri), root, cookies);
            await LoginAsync(cancellation);
            return HttpStatusCode.OK;
        }
        if (settings.Workload == "refresh")
            return await ExchangeAsync(new()
            {
                ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken,
                ["client_id"] = settings.ClientId, ["client_secret"] = settings.ClientSecret
            }, cancellation);
        using var request = new HttpRequestMessage(HttpMethod.Get,
            settings.Workload == "cookie" ? "/account/change-password" : PandaAuthEndpoints.Userinfo);
        if (settings.Workload == "bearer") request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await browser.SendAsync(request, cancellation);
        await response.Content.LoadIntoBufferAsync(cancellation);
        return response.StatusCode;
    }

    private Task LoginAsync(CancellationToken cancellation) => AuthorizeAsync(cancellation, freshLogin: true);

    internal Task AuthorizeSsoAsync(CancellationToken cancellation) => AuthorizeAsync(cancellation, freshLogin: false);

    private async Task AuthorizeAsync(CancellationToken cancellation, bool freshLogin)
    {
        var verifier = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var state = Guid.NewGuid().ToString("N");
        var authorize = QueryHelpers.AddQueryString(PandaAuthEndpoints.Authorization, new Dictionary<string, string?>
        {
            ["client_id"] = settings.ClientId, ["redirect_uri"] = settings.RedirectUri, ["response_type"] = "code",
            ["scope"] = settings.Scopes, ["state"] = state, ["nonce"] = Guid.NewGuid().ToString("N"),
            ["code_challenge_method"] = "S256", ["code_challenge"] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
        });
        using var challenge = await browser.GetAsync(authorize, cancellation);
        Require(challenge.StatusCode == HttpStatusCode.Redirect && challenge.Headers.Location is not null);
        if (!freshLogin)
        {
            await CompleteAuthorizationAsync(challenge, verifier, state, cancellation);
            return;
        }
        var location = challenge.Headers.Location!;
        if (location.IsAbsoluteUri) Require(location.GetLeftPart(UriPartial.Authority) == browser.BaseAddress!.GetLeftPart(UriPartial.Authority));
        var loginPath = location.IsAbsoluteUri ? location.PathAndQuery : location.OriginalString;
        Require(new Uri(browser.BaseAddress!, loginPath).AbsolutePath == "/account/login");
        if (totpSecret is not null)
        {
            await BffLogin.AuthenticateMfaAsync(browser, new Uri(browser.BaseAddress!, loginPath), new Uri(browser.BaseAddress!, authorize),
                settings.UserName, settings.Password, totpSecret, waitForMfaStep, cancellation);
        }
        else
        {
            using var page = await browser.GetAsync(loginPath, cancellation);
            Require(page.IsSuccessStatusCode);
            var csrf = Regex.Match(await page.Content.ReadAsStringAsync(cancellation), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
            Require(csrf.Success);
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = WebUtility.HtmlDecode(csrf.Groups[1].Value), ["UserName"] = settings.UserName,
                ["Password"] = settings.Password, ["ReturnUrl"] = authorize
            });
            using var login = await browser.PostAsync("/account/login", form, cancellation);
            Require(login.StatusCode == HttpStatusCode.Redirect);
        }
        using var authorization = await browser.GetAsync(authorize, cancellation);
        await CompleteAuthorizationAsync(authorization, verifier, state, cancellation);
    }

    private async Task CompleteAuthorizationAsync(HttpResponseMessage authorization, string verifier, string state, CancellationToken cancellation)
    {
        Require(authorization.StatusCode == HttpStatusCode.Redirect && authorization.Headers.Location is not null);
        var callback = BffSnapshot.ResolveOwnedRedirect(browser.BaseAddress!, authorization.Headers.Location!);
        Require(callback.IsAbsoluteUri && callback.GetLeftPart(UriPartial.Path) == settings.RedirectUri);
        var query = QueryHelpers.ParseQuery(callback.Query);
        Require(query.TryGetValue("code", out var code) && code.Count == 1 && !string.IsNullOrEmpty(code.ToString())
            && query.TryGetValue("state", out var returnedState) && returnedState.Count == 1 && returnedState.ToString() == state
            && !query.ContainsKey("error") && string.IsNullOrEmpty(callback.Fragment));
        Require(await ExchangeAsync(new()
        {
            ["client_id"] = settings.ClientId, ["client_secret"] = settings.ClientSecret, ["grant_type"] = "authorization_code",
            ["code"] = code.ToString(), ["redirect_uri"] = settings.RedirectUri, ["code_verifier"] = verifier
        }, cancellation) == HttpStatusCode.OK);
    }

    private async Task<HttpStatusCode> ExchangeAsync(Dictionary<string, string> values, CancellationToken cancellation)
    {
        using var form = new FormUrlEncodedContent(values);
        using var response = await browser.PostAsync(PandaAuthEndpoints.Token, form, cancellation);
        if (response.IsSuccessStatusCode)
        {
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellation));
            accessToken = json.RootElement.GetProperty("access_token").GetString()!;
            refreshToken = json.RootElement.TryGetProperty("refresh_token", out var refresh) ? refresh.GetString()! : refreshToken;
            var lifetime = json.RootElement.GetProperty("expires_in").GetInt32();
            refreshAt = DateTimeOffset.UtcNow.AddSeconds(Math.Max(1, lifetime - Math.Min(30, lifetime / 10)));
            Require(accessToken.Length > 0 && refreshToken.Length > 0);
        }
        return response.StatusCode;
    }

    private static void Require(bool condition) { if (!condition) throw new InvalidOperationException("readiness_protocol_assertion_failed"); }
    internal SessionSnapshot Snapshot() => new(settings.RunId, settings.BaseUri, index, DateTimeOffset.UtcNow,
        cookies.GetAllCookies().Cast<Cookie>().Select(cookie => new SnapshotCookie(cookie.Name, cookie.Value, cookie.Domain,
            cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.Expires)).ToArray(), accessToken, refreshToken);

    internal async Task LogoutAsync()
    {
        using var page = await browser.GetAsync("/account/change-password");
        Require(page.StatusCode == HttpStatusCode.OK);
        var csrf = Regex.Match(await page.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Require(csrf.Success);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = WebUtility.HtmlDecode(csrf.Groups[1].Value) });
        using var response = await browser.PostAsync("/account/logout", form);
        Require(response.StatusCode == HttpStatusCode.Redirect);
    }
    public void Dispose() { if (ownsBrowser) browser.Dispose(); }
}

internal sealed class MixedProtocolUser : IProtocolActor
{
    private readonly ProtocolUser[] users;
    private int next;
    internal MixedProtocolUser(LoadRequest request, int index, X509Certificate2 root)
        => users = new[] { "cookie", "bearer", "refresh", "login" }.Select(workload => new ProtocolUser(request with { Workload = workload }, index, root)).ToArray();
    public Task InitializeAsync(CancellationToken cancellation) => Task.WhenAll(users.Select(user => user.InitializeAsync(cancellation)));
    public Task<HttpStatusCode> StepAsync(CancellationToken cancellation)
        => users[next++ % users.Length].StepAsync(cancellation);
    public void Dispose() { foreach (var user in users) user.Dispose(); }
}
