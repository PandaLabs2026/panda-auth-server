using System.Text.RegularExpressions;

namespace PandaAuth.ReadinessHarness;

public sealed record LoadRequest
{
    public string RunId { get; init; } = "";
    public string BaseUri { get; init; } = "";
    public string RootCertificateFile { get; init; } = "";
    public string Password { get; init; } = "";
    public string ClientSecret { get; init; } = "";
    public string Workload { get; init; } = "";
    public int Concurrency { get; init; }
    public int WarmupSeconds { get; init; } = 30;
    public int DurationSeconds { get; init; } = 120;
    public string StopFile { get; init; } = "";
    public string MigrationConnection { get; init; } = "";
    public string ProbePath { get; init; } = "/healthz";
    public bool RecoveryScenario { get; init; }
    public bool LegacySchema { get; init; }
    public string RecoveryTotpKey { get; init; } = "";
    public string AdminUserName => "r1-admin-" + RunId[..16] + "@example.invalid";

    public string ClientId => "r1-load-" + RunId[..16];
    public string UserName(int index) => $"r1-{RunId[..16]}-{index:D3}";
    public string RedirectUri => new Uri(new Uri(BaseUri), "/callback").AbsoluteUri;

    public void Validate()
    {
        if (!Regex.IsMatch(RunId, "^[0-9a-f]{32}$", RegexOptions.CultureInvariant) ||
            !Uri.TryCreate(BaseUri, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !uri.IsLoopback || uri.Port < 20000 || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 ||
            uri.AbsolutePath != "/" || string.IsNullOrWhiteSpace(RootCertificateFile) ||
            string.IsNullOrWhiteSpace(Password) || string.IsNullOrWhiteSpace(ClientSecret) ||
            Workload is not ("cookie" or "bearer" or "refresh" or "login" or "mixed") ||
            Concurrency is < 1 or > 64 || WarmupSeconds is < 0 or > 300 || DurationSeconds is < 1 or > 1800)
            throw new InvalidOperationException("readiness_load_admission_failed");
        if (StopFile.Length > 0 && Path.GetFileName(StopFile) != "r1-" + RunId + ".stop")
            throw new InvalidOperationException("readiness_stop_path_invalid");
        if (LegacySchema && !RecoveryScenario || ProbePath is not ("/healthz" or "/admin/healthz" or "/me/healthz" or "/admin/api/antiforgery" or "/me/api/antiforgery"))
            throw new InvalidOperationException("readiness_recovery_admission_failed");
        if (RecoveryScenario)
        {
            try
            {
                if (Convert.FromBase64String(RecoveryTotpKey).Length != 32) throw new InvalidOperationException("readiness_recovery_key_invalid");
            }
            catch (FormatException) { throw new InvalidOperationException("readiness_recovery_key_invalid"); }
        }
    }
}
