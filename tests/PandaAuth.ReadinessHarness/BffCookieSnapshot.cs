using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PandaAuth.ReadinessHarness;

public sealed record StoredBffSession(string RunId, string BaseUri, int Index, DateTimeOffset CreatedAt,
    SnapshotCookie[] Cookies, string SubjectSha256);

public static class BffCookieSnapshot
{
    public static void RequireLegacyRejected(HttpStatusCode admin, HttpStatusCode me)
    {
        if (admin != HttpStatusCode.Unauthorized || me is not (HttpStatusCode.OK or HttpStatusCode.Unauthorized or HttpStatusCode.Redirect))
            throw new InvalidOperationException("readiness_legacy_bff_rejection_not_proven");
    }

    public static async Task<object> CreateAsync(LoadRequest settings)
    {
        ProtocolSnapshot.ValidateFile(settings, bff: true);
        using var root = ProtocolSnapshot.Certificate(settings);
        var cookies = new CookieContainer();
        using var browser = ProtocolUser.CreateBrowser(settings, root, cookies);
        var login = await BffLogin.VerifyAsync(settings, browser);
        var snapshot = new StoredBffSession(settings.RunId, settings.BaseUri, settings.SnapshotUserIndex, DateTimeOffset.UtcNow,
            cookies.GetAllCookies().Cast<Cookie>().Select(cookie => new SnapshotCookie(cookie.Name, cookie.Value, cookie.Domain,
                cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.Expires)).ToArray(), login.SubjectSha256);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using (var file = new FileStream(settings.SnapshotFile, options)) await JsonSerializer.SerializeAsync(file, snapshot);
        var checksum = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(settings.SnapshotFile)));
        return new { schema = 1, valid = true, login, snapshotSha256 = checksum };
    }

    public static async Task<object> VerifyAsync(LoadRequest settings, bool legacyRejected = false)
    {
        ProtocolSnapshot.ValidateFile(settings, bff: true);
        var content = await ProtocolSnapshot.ReadPrivateAsync(settings);
        var snapshot = JsonSerializer.Deserialize<StoredBffSession>(content) ?? throw new InvalidOperationException("readiness_bff_snapshot_invalid");
        var now = DateTimeOffset.UtcNow;
        if (snapshot.RunId != settings.RunId || snapshot.BaseUri != settings.BaseUri || snapshot.Index != settings.SnapshotUserIndex ||
            snapshot.CreatedAt > now || now - snapshot.CreatedAt > TimeSpan.FromDays(1) || snapshot.Cookies is null ||
            snapshot.Cookies.Length is < 1 or > 64 || string.IsNullOrEmpty(snapshot.SubjectSha256) ||
            !Regex.IsMatch(snapshot.SubjectSha256, "\\A[a-f0-9]{64}\\z"))
            throw new InvalidOperationException("readiness_bff_snapshot_binding_invalid");
        var cookies = new CookieContainer();
        foreach (var cookie in snapshot.Cookies)
        {
            if (!string.Equals(cookie.Domain?.TrimStart('.'), new Uri(settings.BaseUri).Host, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("readiness_bff_snapshot_cookie_target_invalid");
            cookies.Add(new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
                { Secure = cookie.Secure, HttpOnly = cookie.HttpOnly, Expires = cookie.Expires });
        }
        using var root = ProtocolSnapshot.Certificate(settings);
        using var browser = ProtocolUser.CreateBrowser(settings, root, cookies);
        if (legacyRejected)
        {
            using var oldAdmin = await browser.GetAsync("/admin/api/session");
            using var originalMe = await browser.GetAsync("/me/api/session");
            RequireLegacyRejected(oldAdmin.StatusCode, originalMe.StatusCode);
            return new { schema = 1, valid = true, legacyAdminCookiesRejected = true,
                adminStatus = (int)oldAdmin.StatusCode, meStatus = (int)originalMe.StatusCode };
        }
        var admin = await BffLogin.SessionAsync(browser, "/admin/api/session", requireAdmin: true);
        var me = await BffLogin.SessionAsync(browser, "/me/api/session", requireAdmin: false);
        var subject = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(admin)));
        if (admin != me || subject != snapshot.SubjectSha256) throw new InvalidOperationException("readiness_bff_snapshot_subject_mismatch");
        return new { schema = 1, valid = true, adminStatus = 200, meStatus = 200, subjectSha256 = subject };
    }
}
