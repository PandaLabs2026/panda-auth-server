using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.WebUtilities;
using PandaAuth.Shared;

namespace PandaAuth.ReadinessHarness;

public sealed record BffLoginReport(int Schema, bool Valid, string Scope, bool Mfa, bool SharedSso, string SubjectSha256);

public static class BffLogin
{
    public static async Task<BffLoginReport> VerifyAsync(LoadRequest settings, HttpClient browser)
    {
        settings.Validate();
        if (!settings.RecoveryScenario || browser.BaseAddress?.AbsoluteUri != settings.BaseUri)
            throw new InvalidOperationException("readiness_bff_login_binding_invalid");
        var result=await VerifyCoreAsync(browser,settings.AdminUserName,settings.Password,RecoveryCrypto.SyntheticTotpSecret(settings.RunId));
        return result with{Scope="synthetic_bff_password_totp_sso"};
    }

    internal static async Task<BffLoginReport> VerifyCoreAsync(HttpClient browser,string adminName,string userPassword,byte[] totpSecret)
    {
        var admin = await LoginAsync(browser, "admin", adminName, userPassword, totpSecret);
        var owner = browser.BaseAddress!;
        // Same browser, no second password or TOTP: the IdP session provides SSO.
        await FollowAsync(browser, new Uri(owner, "/me/login?returnUrl=/me/"), "/me/");
        var me = await SessionAsync(browser, "/me/api/session", requireAdmin: false);
        Require(admin == me);
        return new(1, true, "bff_password_totp_sso", true, true,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(admin))));
    }

    internal static async Task<string> LoginAsync(HttpClient browser, string component, string userName, string password,
        byte[] totpSecret, Func<CancellationToken, Task>? waitForStep = null, CancellationToken cancellation = default, Func<string>? currentCode = null)
    {
        Require(component is "admin" or "me");
        var owner = browser.BaseAddress ?? throw new InvalidOperationException("readiness_bff_login_binding_invalid");
        var challenge = component == "admin" ? "/admin/challenge?returnUrl=/admin/" : "/me/login?returnUrl=/me/";
        var login = await FollowAsync(browser, new Uri(owner, challenge), "/account/login", cancellation);
        var query = QueryHelpers.ParseQuery(login.Query);
        Require(query.TryGetValue("returnUrl", out var returnUrl) && returnUrl.Count == 1);
        var authorization = BffSnapshot.ResolveOwnedRedirect(owner, new Uri(returnUrl.ToString(), UriKind.RelativeOrAbsolute));
        Require(authorization.AbsolutePath == PandaAuthEndpoints.Authorization);
        var continuation = await AuthenticateMfaAsync(browser, login, authorization, userName, password, totpSecret, waitForStep, cancellation, currentCode);
        await FollowAsync(browser, continuation, "/" + component + "/", cancellation);
        return await SessionAsync(browser, "/" + component + "/api/session", requireAdmin: component == "admin");
    }

    internal static async Task<Uri> AuthenticateMfaAsync(HttpClient browser, Uri login, Uri authorization,
        string userName, string password, byte[] totpSecret, Func<CancellationToken, Task>? waitForStep = null,
        CancellationToken cancellation = default, Func<string>? currentCode = null)
    {
        var owner = browser.BaseAddress ?? throw new InvalidOperationException("readiness_bff_login_binding_invalid");
        login = BffSnapshot.ResolveOwnedRedirect(owner, login);
        authorization = BffSnapshot.ResolveOwnedRedirect(owner, authorization);
        Require(login.AbsolutePath == "/account/login" && authorization.AbsolutePath == PandaAuthEndpoints.Authorization
            && ((totpSecret.Length == 20 && currentCode is null) || (totpSecret.Length == 0 && currentCode is not null)));
        using var page = await browser.GetAsync(login, cancellation);
        Require(page.StatusCode == HttpStatusCode.OK);
        using var credentials = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = Csrf(await page.Content.ReadAsStringAsync()),
            ["UserName"] = userName, ["Password"] = password,
            ["ReturnUrl"] = authorization.PathAndQuery
        });
        using var passwordResponse = await browser.PostAsync("/account/login", credentials, cancellation);
        var challenge = Redirect(owner, passwordResponse);
        Require(challenge.AbsolutePath == "/account/mfa/challenge");
        using var mfaPage = await browser.GetAsync(challenge, cancellation);
        Require(mfaPage.StatusCode == HttpStatusCode.OK);
        // Source and restored factors retain normal server anti-replay checks.
        // Generated codes wait for a new step. A supplied code is obtained at
        // submission time and must not be delayed into a later step.
        if (currentCode is null)
        {
            var delay = 32 - DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 30;
            if (waitForStep is null) await Task.Delay(TimeSpan.FromSeconds(delay), cancellation);
            else await waitForStep(cancellation);
        }
        var code = currentCode is null ? BffSnapshot.TotpCode(totpSecret, DateTimeOffset.UtcNow) : currentCode();
        Require(code.Length == 6 && code.All(c => c is >= '0' and <= '9'));
        using var factor = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = Csrf(await mfaPage.Content.ReadAsStringAsync()),
            ["Code"] = code,
            ["ReturnUrl"] = authorization.PathAndQuery
        });
        using var mfa = await browser.PostAsync("/account/mfa/challenge/totp", factor, cancellation);
        var continuation = Redirect(owner, mfa);
        Require(continuation.AbsolutePath == PandaAuthEndpoints.Authorization);
        return continuation;
    }

    internal static async Task<string> SessionAsync(HttpClient browser, string path, bool requireAdmin)
    {
        using var response = await browser.GetAsync(path);
        Require(response.StatusCode == HttpStatusCode.OK);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var subject = json.RootElement.GetProperty("subject").GetString();
        Require(!string.IsNullOrWhiteSpace(subject));
        if (requireAdmin)
            Require(json.RootElement.GetProperty("roles").EnumerateArray().Any(value => value.GetString() == PandaAuthRoles.Admin));
        return subject!;
    }

    private static async Task<Uri> FollowAsync(HttpClient browser, Uri initial, string stopPath, CancellationToken cancellation = default)
    {
        var target = BffSnapshot.ResolveOwnedRedirect(browser.BaseAddress!, initial);
        for (var redirects = 0; redirects < 12; redirects++)
        {
            if (target.AbsolutePath == stopPath) return target;
            using var response = await browser.GetAsync(target, cancellation);
            target = Redirect(browser.BaseAddress!, response);
        }
        throw new InvalidOperationException("readiness_bff_redirect_budget_exceeded");
    }

    private static Uri Redirect(Uri owner, HttpResponseMessage response,[CallerLineNumber]int line=0)
    {
        if(response.StatusCode != HttpStatusCode.Redirect || response.Headers.Location is null)
        {
            var error=new InvalidOperationException("readiness_bff_login_protocol_failed");
            error.Data["bffLine"]=line;error.Data["bffStatus"]=(int)response.StatusCode;throw error;
        }
        return BffSnapshot.ResolveOwnedRedirect(owner, response.Headers.Location!);
    }

    private static string Csrf(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        Require(match.Success);
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    private static void Require(bool condition,[CallerLineNumber]int line=0)
    {
        if (!condition)
        {
            var error=new InvalidOperationException("readiness_bff_login_protocol_failed");error.Data["bffLine"]=line;throw error;
        }
    }
}
