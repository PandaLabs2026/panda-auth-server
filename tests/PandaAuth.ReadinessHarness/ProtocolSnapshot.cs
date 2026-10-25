using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using PandaAuth.Shared;

namespace PandaAuth.ReadinessHarness;

// Opaque cookies/tokens only enter a private task file; never stdout or receipts.
public sealed record SnapshotCookie(string Name, string Value, string Domain, string Path, bool Secure, bool HttpOnly, DateTime Expires);
public sealed record SessionSnapshot(string RunId, string BaseUri, int UserIndex, DateTimeOffset CreatedAt,
    SnapshotCookie[] Cookies, string AccessToken, string RefreshToken);

public sealed class SnapshotProtocolException(HttpStatusCode cookie, HttpStatusCode bearer, HttpStatusCode refresh,
    bool loginRedirect, string error, Uri? owner = null, Uri? location = null) : InvalidOperationException("readiness_snapshot_protocol_failed")
{
    public bool RedirectOwnerMatches { get; } = owner is not null && location is not null &&
        new Uri(owner, location).GetLeftPart(UriPartial.Authority) == owner.GetLeftPart(UriPartial.Authority);
    public string RedirectScheme { get; } = owner is not null && location is not null
        ? new Uri(owner, location).Scheme switch { "https" => "https", "http" => "http", _ => "other" } : "none";
    public string RedirectPath { get; } = owner is not null && location is not null
        ? new Uri(owner, location).AbsolutePath switch { "/account/login" => "login", "/Account/Login" => "login-capitalized", _ => "other" } : "none";
    public int CookieStatus { get; } = (int)cookie;
    public int BearerStatus { get; } = (int)bearer;
    public int RefreshStatus { get; } = (int)refresh;
    public bool LoginRedirect { get; } = loginRedirect;
    public string RefreshError { get; } = error is "invalid_grant" or "invalid_client" or "invalid_token" or "invalid_scope"
        or "server_error" or "temporarily_unavailable" or "unauthorized_client" or "none" or "malformed" ? error : "other";
}

public static class ProtocolSnapshot
{
    public static void ValidateFile(LoadRequest settings)
    {
        settings.Validate();
        if (settings.SnapshotUserIndex is < 0 or > 1 || string.IsNullOrWhiteSpace(settings.SnapshotFile) ||
            !Path.IsPathFullyQualified(settings.SnapshotFile) || Path.GetFileName(settings.SnapshotFile) !=
            $"panda-r1-session-{settings.RunId}-{settings.SnapshotUserIndex}.json")
            throw new InvalidOperationException("readiness_snapshot_path_invalid");
        var directory = Path.GetDirectoryName(Path.GetFullPath(settings.SnapshotFile))!;
        var temporary = Path.GetFullPath(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath());
        var relative = Path.GetRelativePath(temporary, directory);
        var inTemporary = relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar) && !Path.IsPathRooted(relative);
        var isolated = OperatingSystem.IsLinux() && File.Exists("/.dockerenv") && directory == "/fixture" &&
            Environment.GetEnvironmentVariable("PANDA_AUTH_R1_ISOLATED_RUN") == settings.RunId;
        if (!inTemporary && !isolated) throw new InvalidOperationException("readiness_snapshot_path_invalid");
        if (File.Exists(settings.SnapshotFile) && File.GetAttributes(settings.SnapshotFile).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException("readiness_snapshot_link_invalid");
    }

    public static async Task<object> CreateAsync(LoadRequest settings, bool revoke)
    {
        ValidateFile(settings);
        using var root = Certificate(settings);
        using var user = new ProtocolUser(settings, settings.SnapshotUserIndex, root);
        await user.InitializeAsync(CancellationToken.None);
        if (await user.StepAsync(CancellationToken.None) != HttpStatusCode.OK) throw new InvalidOperationException("readiness_snapshot_source_failed");
        var snapshot = user.Snapshot();
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using (var file = new FileStream(settings.SnapshotFile, options)) await JsonSerializer.SerializeAsync(file, snapshot);
        var checksum = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(settings.SnapshotFile)));
        if (revoke) await user.LogoutAsync();
        return new { schema = 1, valid = true, revoked = revoke, snapshotSha256 = checksum };
    }

    public static async Task<object> VerifyAsync(LoadRequest settings, bool rejected)
    {
        ValidateFile(settings);
        if (!Regex.IsMatch(settings.SnapshotSha256, "\\A[a-f0-9]{64}\\z") || new FileInfo(settings.SnapshotFile).Length > 131072)
            throw new InvalidOperationException("readiness_snapshot_file_invalid");
        var content = await File.ReadAllBytesAsync(settings.SnapshotFile);
        if (Convert.ToHexStringLower(SHA256.HashData(content)) != settings.SnapshotSha256)
            throw new InvalidOperationException("readiness_snapshot_hash_mismatch");
        if (!OperatingSystem.IsWindows() && File.GetUnixFileMode(settings.SnapshotFile) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
            throw new InvalidOperationException("readiness_snapshot_permissions_invalid");
        var snapshot = JsonSerializer.Deserialize<SessionSnapshot>(content) ?? throw new InvalidOperationException("readiness_snapshot_invalid");
        var now = DateTimeOffset.UtcNow;
        if (snapshot.RunId != settings.RunId || snapshot.BaseUri != settings.BaseUri || snapshot.UserIndex != settings.SnapshotUserIndex ||
            snapshot.CreatedAt > now || now - snapshot.CreatedAt > TimeSpan.FromDays(1) || snapshot.Cookies is null ||
            snapshot.Cookies.Length is < 1 or > 64 || string.IsNullOrEmpty(snapshot.AccessToken) || string.IsNullOrEmpty(snapshot.RefreshToken))
            throw new InvalidOperationException("readiness_snapshot_binding_invalid");
        var cookies = new CookieContainer();
        var host = new Uri(settings.BaseUri).Host;
        foreach (var cookie in snapshot.Cookies)
        {
            if (!string.Equals(cookie.Domain.TrimStart('.'), host, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("readiness_snapshot_cookie_target_invalid");
            cookies.Add(new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
                { Secure = cookie.Secure, HttpOnly = cookie.HttpOnly, Expires = cookie.Expires });
        }
        using var root = Certificate(settings);
        using var browser = ProtocolUser.CreateBrowser(settings, root, cookies);
        using var cookieResponse = await browser.GetAsync("/account/change-password");
        using var bearer = new HttpRequestMessage(HttpMethod.Get, PandaAuthEndpoints.Userinfo);
        bearer.Headers.Authorization = new AuthenticationHeaderValue("Bearer", snapshot.AccessToken);
        using var bearerResponse = await browser.SendAsync(bearer);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = snapshot.RefreshToken,
            ["client_id"] = settings.ClientId, ["client_secret"] = settings.ClientSecret
        });
        using var refresh = await browser.PostAsync(PandaAuthEndpoints.Token, form);
        var loginRedirect = cookieResponse.StatusCode == HttpStatusCode.Redirect && cookieResponse.Headers.Location is { } location &&
            (!location.IsAbsoluteUri || location.GetLeftPart(UriPartial.Authority) == browser.BaseAddress!.GetLeftPart(UriPartial.Authority)) &&
            (location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString).StartsWith("/account/login", StringComparison.Ordinal);
        var refreshError = "none";
        if (refresh.StatusCode == HttpStatusCode.BadRequest)
        {
            try
            {
                using var error = JsonDocument.Parse(await refresh.Content.ReadAsStringAsync());
                refreshError = error.RootElement.TryGetProperty("error", out var value) && value.ValueKind == JsonValueKind.String
                    ? value.GetString()! : "malformed";
            }
            catch (JsonException) { refreshError = "malformed"; }
        }
        var valid = cookieResponse.StatusCode == HttpStatusCode.OK && bearerResponse.StatusCode == HttpStatusCode.OK && refresh.StatusCode == HttpStatusCode.OK;
        if (rejected)
        {
            valid = (loginRedirect || cookieResponse.StatusCode == HttpStatusCode.Unauthorized) &&
                bearerResponse.StatusCode == HttpStatusCode.Unauthorized && refresh.StatusCode == HttpStatusCode.BadRequest &&
                refreshError == "invalid_grant";
        }
        if (!valid) throw new SnapshotProtocolException(cookieResponse.StatusCode, bearerResponse.StatusCode, refresh.StatusCode, loginRedirect, refreshError,
            browser.BaseAddress, cookieResponse.Headers.Location);
        return new { schema = 1, valid = true, rejected, cookieStatus = (int)cookieResponse.StatusCode,
            bearerStatus = (int)bearerResponse.StatusCode, refreshStatus = (int)refresh.StatusCode };
    }

    private static X509Certificate2 Certificate(LoadRequest settings)
    {
        var root = X509CertificateLoader.LoadCertificateFromFile(settings.RootCertificateFile);
        if (root.GetNameInfo(X509NameType.SimpleName, false) != "panda-auth-r1-" + settings.RunId)
        {
            root.Dispose();
            throw new InvalidOperationException("readiness_fixture_certificate_mismatch");
        }
        return root;
    }
}
