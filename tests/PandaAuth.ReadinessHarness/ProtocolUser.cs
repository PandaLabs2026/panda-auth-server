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

internal sealed class ProtocolUser : IProtocolActor
{
    private readonly LoadRequest settings;
    private readonly int index;
    private readonly X509Certificate2 root;
    private CookieContainer cookies = new();
    private HttpClient browser;
    private string accessToken = "";
    private string refreshToken = "";
    private DateTimeOffset refreshAt;

    internal ProtocolUser(LoadRequest settings, int index, X509Certificate2 root)
    {
        this.settings = settings; this.index = index; this.root = root;
        browser = CreateBrowser(settings, root, cookies);
    }

    internal static HttpClient CreateBrowser(LoadRequest settings, X509Certificate2 root, CookieContainer? cookies = null)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false, CookieContainer = cookies ?? new CookieContainer(), UseProxy = false };
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
        {
            if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0)
                return false;
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(certificate);
        };
        return new HttpClient(handler) { BaseAddress = new Uri(settings.BaseUri), Timeout = TimeSpan.FromSeconds(15) };
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
            browser.Dispose();
            cookies = new CookieContainer();
            browser = CreateBrowser(settings, root, cookies);
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

    private async Task LoginAsync(CancellationToken cancellation)
    {
        var verifier = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var authorize = QueryHelpers.AddQueryString(PandaAuthEndpoints.Authorization, new Dictionary<string, string?>
        {
            ["client_id"] = settings.ClientId, ["redirect_uri"] = settings.RedirectUri, ["response_type"] = "code",
            ["scope"] = "openid profile offline_access", ["state"] = Guid.NewGuid().ToString("N"), ["nonce"] = Guid.NewGuid().ToString("N"),
            ["code_challenge_method"] = "S256", ["code_challenge"] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
        });
        using var challenge = await browser.GetAsync(authorize, cancellation);
        Require(challenge.StatusCode == HttpStatusCode.Redirect && challenge.Headers.Location is not null);
        var location = challenge.Headers.Location!;
        if (location.IsAbsoluteUri) Require(location.GetLeftPart(UriPartial.Authority) == browser.BaseAddress!.GetLeftPart(UriPartial.Authority));
        var loginPath = location.IsAbsoluteUri ? location.PathAndQuery : location.OriginalString;
        Require(loginPath.StartsWith("/account/login", StringComparison.Ordinal));
        using var page = await browser.GetAsync(loginPath, cancellation);
        Require(page.IsSuccessStatusCode);
        var csrf = Regex.Match(await page.Content.ReadAsStringAsync(cancellation), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Require(csrf.Success);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(csrf.Groups[1].Value), ["UserName"] = settings.UserName(index),
            ["Password"] = settings.Password, ["ReturnUrl"] = authorize
        });
        using var login = await browser.PostAsync("/account/login", form, cancellation);
        Require(login.StatusCode == HttpStatusCode.Redirect);
        using var authorization = await browser.GetAsync(authorize, cancellation);
        Require(authorization.StatusCode == HttpStatusCode.Redirect && authorization.Headers.Location is not null);
        var callback = authorization.Headers.Location!;
        Require(callback.IsAbsoluteUri && callback.GetLeftPart(UriPartial.Path) == settings.RedirectUri);
        var query = QueryHelpers.ParseQuery(callback.Query);
        Require(query.TryGetValue("code", out var code) && code.Count == 1);
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
    public void Dispose() => browser.Dispose();
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
