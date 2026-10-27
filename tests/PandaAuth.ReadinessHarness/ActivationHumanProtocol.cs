using System.Net;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;

namespace PandaAuth.ReadinessHarness;

internal sealed record ActivationHumanIdentity(string UserName, string Password, string TotpSecret, string SubjectSha256, string UsernameSha256);
internal sealed record ActivationHumanInput(int Schema, string Instance, string Component, string Attempt, string SourceSha256,
    string PolicySha256, string RuntimesSha256, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, string Issuer,
    string ClientId, string ClientSecret, string RedirectUri, ActivationHumanIdentity Identity, ActivationHumanIdentity? Restricted,
    string? RootCertificateSha256 = null);

/// <summary>Component protocol evidence only. The verified receiver owns approval,
/// current account/client preflight, helper provenance and authoritative receipts.</summary>
public static class ActivationHumanProtocol
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    [DllImport("libc")] private static extern uint geteuid();
    private static void Require([DoesNotReturnIf(false)] bool value) { if (!value) throw new InvalidOperationException("activation_human_failed"); }
    private static string Sha(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static bool Hex(string? value, int length) => value is not null && value.Length == length
        && Regex.IsMatch(value, "^[a-f0-9]{" + length + "}$", RegexOptions.CultureInvariant);

    internal static ActivationHumanInput Parse(string line, Func<string, string?> environment, DateTimeOffset now)
    {
        var input = ControlledTransport.Decode<ActivationHumanInput>(line);
        Validate(input, now);
        Require(environment("PANDA_AUTH_ACTIVATION_INPUT_SHA256") == Sha(line)
            && environment("PANDA_AUTH_ACTIVATION_POLICY_SHA256") == input.PolicySha256
            && environment("PANDA_AUTH_ACTIVATION_SOURCE_SHA256") == input.SourceSha256
            && environment("PANDA_AUTH_ACTIVATION_RUNTIMES_SHA256") == input.RuntimesSha256
            && environment("PANDA_AUTH_ACTIVATION_ATTEMPT") == input.Attempt);
        return input;
    }

    private static void Validate(ActivationHumanInput input, DateTimeOffset now)
    {
        Require(input.Schema == 1 && input.Instance is "fleet" or "t0000" && input.Component is "admin" or "me"
            && Hex(input.Attempt, 32) && Hex(input.SourceSha256, 64) && Hex(input.PolicySha256, 64) && Hex(input.RuntimesSha256, 64)
            && input.CreatedAt > DateTimeOffset.UnixEpoch && input.CreatedAt <= now && now < input.ExpiresAt
            && input.ExpiresAt - input.CreatedAt <= TimeSpan.FromDays(1));
        var issuer = input.Instance == "fleet" ? "https://auth.appliket.com/" : "https://t0000-auth.s001.pandalabs.cn/";
        Require(input.Issuer == issuer && input.ClientId == (input.Component == "admin" ? FirstPartyClients.AdminWeb : FirstPartyClients.MeWeb)
            && input.ClientSecret is { Length: > 0 and <= 4096 });
        Require(Uri.TryCreate(input.RedirectUri, UriKind.Absolute, out var callback)
            && callback.Scheme == "https" && callback.GetLeftPart(UriPartial.Authority) == new Uri(issuer).GetLeftPart(UriPartial.Authority)
            && callback.UserInfo.Length == 0 && callback.Query.Length == 0 && callback.Fragment.Length == 0
            && callback.AbsolutePath.StartsWith("/" + input.Component + "/callback/", StringComparison.Ordinal));
        Identity(input.Identity);
        if (input.Component == "admin")
        {
            Require(input.Restricted is not null);
            Identity(input.Restricted!);
            Require(input.Restricted!.SubjectSha256 != input.Identity.SubjectSha256 && input.Restricted.UsernameSha256 != input.Identity.UsernameSha256);
        }
        else Require(input.Restricted is null);
        Require(input.RootCertificateSha256 is null || Hex(input.RootCertificateSha256, 64));
    }

    private static void Identity(ActivationHumanIdentity value)
    {
        Require(value is not null && value.UserName is { Length: > 0 and <= 256 } && value.UserName == value.UserName.Trim()
            && !value.UserName.Any(char.IsControl)
            && value.Password is { Length: > 0 and <= 1024 } && Hex(value.SubjectSha256, 64)
            && Hex(value.UsernameSha256, 64) && Sha(value.UserName) == value.UsernameSha256 && value.TotpSecret is { Length: 28 });
        var seed = Convert.FromBase64String(value.TotpSecret);
        try { Require(seed.Length == 20 && Convert.ToBase64String(seed) == value.TotpSecret); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    public static async Task<int> Dispatch(string line)
    {
        try
        {
            Require(OperatingSystem.IsLinux() && geteuid() == 1654);
            var input = Parse(line, Environment.GetEnvironmentVariable, DateTimeOffset.UtcNow);
            using var root = Root(input);
            void Check() => Parse(line, Environment.GetEnvironmentVariable, DateTimeOffset.UtcNow);
            HttpClient Browser(CookieContainer cookies)
            {
                var browser = ProtocolUser.CreateBrowser(new Uri(input.Issuer), root, cookies, request =>
                {
                    Check();
                    Require(request.RequestUri is { Scheme: "https" } uri && uri.UserInfo.Length == 0
                        && uri.GetLeftPart(UriPartial.Authority) == new Uri(input.Issuer).GetLeftPart(UriPartial.Authority));
                });
                // Keep the standard certificate/hostname verification supplied
                // by CreateBrowser; this is not a permissive TLS callback.
                return browser;
            }
            var report = await RunCoreAsync(input, Browser, Check);
            Check();
            Console.WriteLine(JsonSerializer.Serialize(report, Json));
            return 0;
        }
        catch (Exception)
        {
            Console.WriteLine("{\"schema\":1,\"valid\":false,\"scope\":\"activation-human-component\",\"code\":\"activation_human_failed\"}");
            return 2;
        }
    }

    private static X509Certificate2? Root(ActivationHumanInput input)
    {
        const string path = "/run/pandalabs/auth-activation/ca.pem";
        if (input.RootCertificateSha256 is null) { Require(!File.Exists(path)); return null; }
        var file = new FileInfo(path);
        Require(file.Exists && file.LinkTarget is null && file.Length is > 0 and <= 65536);
        var bytes = File.ReadAllBytes(path);
        Require(bytes.Length is > 0 and <= 65536 && Convert.ToHexStringLower(SHA256.HashData(bytes)) == input.RootCertificateSha256);
        var root = X509CertificateLoader.LoadCertificate(bytes);
        if (!root.Extensions.OfType<X509BasicConstraintsExtension>().Any(extension => extension.CertificateAuthority))
        { root.Dispose(); throw new InvalidOperationException("activation_human_failed"); }
        return root;
    }

    internal static async Task<object> RunCoreAsync(ActivationHumanInput input, Func<CookieContainer, HttpClient> browserFactory,
        Action checkpoint, Func<CancellationToken, Task>? waitForStep = null)
    {
        Validate(input, DateTimeOffset.UtcNow);
        await Actor(input.Identity, bff: true, input.Component == "admin" ? HttpStatusCode.OK : null);
        if (input.Component == "admin") await Actor(input.Restricted!, bff: false, HttpStatusCode.Forbidden);
        checkpoint();
        var assertions = new Dictionary<string, bool> { ["freshReauthentication"] = true, ["mfaVerified"] = true,
            ["refreshVerified"] = true, ["logoutVerified"] = true, ["revocationVerified"] = true };
        if (input.Component == "admin") assertions["roleIsolation"] = true;
        return new { schema = 1, valid = true, scope = "activation-human-component", input.Instance, input.Component, input.Attempt,
            input.SourceSha256, input.PolicySha256, input.RuntimesSha256, subjectSha256 = input.Identity.SubjectSha256, assertions };

        async Task Actor(ActivationHumanIdentity identity, bool bff, HttpStatusCode? resourceStatus)
        {
            var seed = Convert.FromBase64String(identity.TotpSecret);
            var cookies = new CookieContainer();
            using var browser = browserFactory(cookies);
            var pending = new List<SessionSnapshot>();
            ProtocolUser? actor = null;
            var ownedLogin = false;
            var loggedOut = false;
            try
            {
                checkpoint();
                if (bff)
                {
                    var subject = await BffLogin.LoginAsync(browser, input.Component, identity.UserName, identity.Password, seed, waitForStep);
                    Require(Sha(subject) == identity.SubjectSha256);
                    ownedLogin = true;
                }
                var scopes = "openid profile email roles offline_access" + (input.Component == "admin" ? " " + PandaAuthAdminApi.Scope : "");
                var settings = new ProtocolActorSettings(input.Attempt, input.Issuer, identity.Password, input.ClientId, input.ClientSecret,
                    input.RedirectUri, identity.UserName, "cookie", scopes);
                actor = new ProtocolUser(settings, 0, browser, cookies, seed, waitForStep);
                if (bff) await actor.AuthorizeSsoAsync(CancellationToken.None);
                else await actor.InitializeAsync(CancellationToken.None);
                var snapshot = actor.Snapshot();
                var subjectId = await Subject(browser, snapshot.AccessToken, identity.SubjectSha256);
                ownedLogin = true;
                pending.Add(snapshot);
                if (resourceStatus is not null)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, PandaAuthAdminApi.User(subjectId));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", snapshot.AccessToken);
                    using var response = await browser.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                    Require(response.StatusCode == resourceStatus);
                }
                checkpoint();
                var oldRefresh = snapshot.RefreshToken;
                await ProtocolSnapshot.VerifyCoreAsync(browser, snapshot, input.ClientId, input.ClientSecret, false, subjectId,
                    (access, refresh) => snapshot = snapshot with { AccessToken = access, RefreshToken = refresh });
                Require(snapshot.RefreshToken != oldRefresh);
                await Subject(browser, snapshot.AccessToken, identity.SubjectSha256);
                pending.Add(snapshot);
                checkpoint();
                foreach (var pair in pending.ToArray())
                {
                    await RevokeAsync(browser, input, pair);
                    await TokensRejected(browser, input, pair);
                    pending.Remove(pair);
                }
                if (bff) await RpLogout(browser, input.Component);
                else await actor.LogoutAsync();
                loggedOut = true;
                checkpoint();
                using var replay = browserFactory(Cookies(snapshot, input.Issuer));
                await ProtocolSnapshot.VerifyCoreAsync(replay, snapshot, input.ClientId, input.ClientSecret, true);
                if (bff)
                {
                    using var response = await replay.GetAsync("/" + input.Component + "/api/session");
                    Require(response.StatusCode == HttpStatusCode.Unauthorized);
                }
                checkpoint();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                // Only pairs whose actual userinfo matched the approved actor
                // enter this list; never revoke an arbitrary user's tokens.
                try
                {
                    foreach (var pair in pending) { checkpoint(); await RevokeAsync(browser, input, pair); }
                    if (ownedLogin && !loggedOut)
                    {
                        checkpoint();
                        if (bff) await RpLogout(browser, input.Component);
                        else if (actor is not null) await actor.LogoutAsync();
                    }
                }
                finally { actor?.Dispose(); }
            }
        }
    }

    private static async Task<string> Subject(HttpClient browser, string access, string expected)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, PandaAuthEndpoints.Userinfo);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        using var response = await browser.SendAsync(request);
        Require(response.StatusCode == HttpStatusCode.OK);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var subject = body.RootElement.GetProperty("sub").GetString();
        Require(subject is not null && Sha(subject) == expected);
        return subject!;
    }

    internal static async Task RevokeAsync(HttpClient browser, ActivationHumanInput input, SessionSnapshot snapshot)
    {
        Require(browser.BaseAddress?.AbsoluteUri == input.Issuer && snapshot.RunId == input.Attempt && snapshot.BaseUri == input.Issuer);
        foreach (var (token, hint) in new[] { (snapshot.AccessToken, "access_token"), (snapshot.RefreshToken, "refresh_token") })
        {
            Require(token is { Length: > 0 and <= 32768 });
            using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token, ["token_type_hint"] = hint,
                ["client_id"] = input.ClientId, ["client_secret"] = input.ClientSecret });
            using var response = await browser.PostAsync(PandaAuthEndpoints.Revocation, form);
            Require(response.StatusCode == HttpStatusCode.OK);
        }
    }

    private static async Task TokensRejected(HttpClient browser, ActivationHumanInput input, SessionSnapshot snapshot)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, PandaAuthEndpoints.Userinfo);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", snapshot.AccessToken);
        using var bearer = await browser.SendAsync(request);
        Require(bearer.StatusCode == HttpStatusCode.Unauthorized);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "refresh_token",
            ["refresh_token"] = snapshot.RefreshToken, ["client_id"] = input.ClientId, ["client_secret"] = input.ClientSecret });
        using var refresh = await browser.PostAsync(PandaAuthEndpoints.Token, form);
        Require(refresh.StatusCode == HttpStatusCode.BadRequest);
        using var body = JsonDocument.Parse(await refresh.Content.ReadAsStringAsync());
        Require(body.RootElement.GetProperty("error").GetString() == "invalid_grant");
    }

    private static async Task RpLogout(HttpClient browser, string component)
    {
        using var response = await browser.GetAsync("/" + component + "/api/antiforgery");
        Require(response.StatusCode == HttpStatusCode.OK);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = body.RootElement.GetProperty("token").GetString();
        Require(!string.IsNullOrEmpty(token));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/" + component + "/api/logout");
        request.Headers.Add("X-XSRF-Token", token);
        using var logout = await browser.SendAsync(request);
        Require(logout.StatusCode == HttpStatusCode.Redirect && logout.Headers.Location is not null);
        BffSnapshot.ResolveOwnedRedirect(browser.BaseAddress!, logout.Headers.Location!);
    }

    private static CookieContainer Cookies(SessionSnapshot snapshot, string issuer)
    {
        var result = new CookieContainer();
        Require(snapshot.Cookies.Length is > 0 and <= 128);
        foreach (var cookie in snapshot.Cookies)
        {
            Require(cookie.Domain.TrimStart('.').Equals(new Uri(issuer).Host, StringComparison.OrdinalIgnoreCase) && cookie.Secure);
            result.Add(new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
                { Secure = cookie.Secure, HttpOnly = cookie.HttpOnly, Expires = cookie.Expires });
        }
        return result;
    }
}
