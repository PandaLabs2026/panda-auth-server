using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace PandaAuth.ReadinessHarness;

public static class DefaultLimitProbe
{
    public static async Task<object> RunAsync(LoadRequest input, bool account)
    {
        input.Validate();
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(input.RootCertificateFile);
        if (certificate.GetNameInfo(X509NameType.SimpleName, false) != "panda-auth-r1-" + input.RunId)
            throw new InvalidOperationException("readiness_fixture_certificate_mismatch");
        using var browser = ProtocolUser.CreateBrowser(input, certificate);
        using var page = await browser.GetAsync("/account/login");
        page.EnsureSuccessStatusCode();
        var csrf = Regex.Match(await page.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        if (!csrf.Success) throw new InvalidOperationException("readiness_csrf_missing");
        var allowed = account ? 5 : 10;
        for (var index = 0; index <= allowed + 1; index++)
        {
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = WebUtility.HtmlDecode(csrf.Groups[1].Value),
                ["UserName"] = "r1-probe-" + input.RunId + (account ? "" : "-" + index),
                ["Password"] = "Intentionally-invalid-synthetic-password", ["ReturnUrl"] = "/account/change-password"
            });
            using var request = new HttpRequestMessage(HttpMethod.Post, "/account/login") { Content = form };
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", "198.51.100." + (index + 1));
            using var response = await browser.SendAsync(request);
            if (index < allowed && response.StatusCode != HttpStatusCode.OK ||
                index >= allowed && (response.StatusCode != HttpStatusCode.TooManyRequests || response.Headers.RetryAfter is null))
                throw new InvalidOperationException("readiness_default_limit_failed");
        }
        return new { schema = 1, valid = true, dimension = account ? "account" : "ip", allowed,
            forwardedHeaderBypassRejected = true };
    }
}
