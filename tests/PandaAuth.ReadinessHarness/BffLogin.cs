using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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
        var owner = browser.BaseAddress;
        var login = await FollowAsync(browser, new Uri(owner, "/admin/challenge?returnUrl=/admin/"), "/account/login");
        var query = QueryHelpers.ParseQuery(login.Query);
        Require(query.TryGetValue("returnUrl", out var returnUrl) && returnUrl.Count == 1);
        var authorization = BffSnapshot.ResolveOwnedRedirect(owner, new Uri(returnUrl.ToString(), UriKind.RelativeOrAbsolute));
        Require(authorization.AbsolutePath == PandaAuthEndpoints.Authorization);
        using var page = await browser.GetAsync(login);
        Require(page.StatusCode == HttpStatusCode.OK);
        using var credentials = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = Csrf(await page.Content.ReadAsStringAsync()),
            ["UserName"] = settings.AdminUserName, ["Password"] = settings.Password,
            ["ReturnUrl"] = authorization.PathAndQuery
        });
        using var password = await browser.PostAsync("/account/login", credentials);
        var challenge = Redirect(owner, password);
        Require(challenge.AbsolutePath == "/account/mfa/challenge");
        using var mfaPage = await browser.GetAsync(challenge);
        Require(mfaPage.StatusCode == HttpStatusCode.OK);
        // Source and restored factors retain anti-replay state. Use a fresh real
        // time step rather than weakening that state or retrying reused codes.
        var delay = 32 - DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 30;
        await Task.Delay(TimeSpan.FromSeconds(delay));
        using var factor = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = Csrf(await mfaPage.Content.ReadAsStringAsync()),
            ["Code"] = BffSnapshot.TotpCode(RecoveryCrypto.SyntheticTotpSecret(settings.RunId), DateTimeOffset.UtcNow),
            ["ReturnUrl"] = authorization.PathAndQuery
        });
        using var mfa = await browser.PostAsync("/account/mfa/challenge/totp", factor);
        var continuation = Redirect(owner, mfa);
        Require(continuation.AbsolutePath == PandaAuthEndpoints.Authorization);
        await FollowAsync(browser, continuation, "/admin/");
        var admin = await SessionAsync(browser, "/admin/api/session", requireAdmin: true);
        // Same browser, no second password or TOTP: the IdP session provides SSO.
        await FollowAsync(browser, new Uri(owner, "/me/login?returnUrl=/me/"), "/me/");
        var me = await SessionAsync(browser, "/me/api/session", requireAdmin: false);
        Require(admin == me);
        return new(1, true, "synthetic_bff_password_totp_sso", true, true,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(admin))));
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

    private static async Task<Uri> FollowAsync(HttpClient browser, Uri initial, string stopPath)
    {
        var target = BffSnapshot.ResolveOwnedRedirect(browser.BaseAddress!, initial);
        for (var redirects = 0; redirects < 12; redirects++)
        {
            if (target.AbsolutePath == stopPath) return target;
            using var response = await browser.GetAsync(target);
            target = Redirect(browser.BaseAddress!, response);
        }
        throw new InvalidOperationException("readiness_bff_redirect_budget_exceeded");
    }

    private static Uri Redirect(Uri owner, HttpResponseMessage response)
    {
        Require(response.StatusCode == HttpStatusCode.Redirect && response.Headers.Location is not null);
        return BffSnapshot.ResolveOwnedRedirect(owner, response.Headers.Location!);
    }

    private static string Csrf(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        Require(match.Success);
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("readiness_bff_login_protocol_failed");
    }
}
