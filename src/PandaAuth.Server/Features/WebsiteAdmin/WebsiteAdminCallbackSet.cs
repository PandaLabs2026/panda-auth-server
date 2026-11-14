using System.Text.Json;

namespace PandaAuth.Server.Features.WebsiteAdmin;

internal sealed class WebsiteAdminCallbackSet
{
    private const string CanonicalAdmin = "https://operation.appliket.com/operation/";
    private const string CompatibilityAdmin = "https://appliket.com/operation/";
    private const string CanonicalCollector = "https://operation.appliket.com/_telemetry/";
    private const string CompatibilityCollector = "https://appliket.com/_telemetry/";
    // v4 迁移窗口（meta 形状 v2 序列①，2026-11-14）：canonical=operation.pandacloud.cc，
    // 退役域 operation.appliket.com 进 compatibility 双注册；退役批再收口为单新根。
    private const string MigratingRoot = "https://operation.pandacloud.cc/";
    private const string MigratingCollector = "https://operation.pandacloud.cc/_telemetry/";
    private const string RetiringRoot = "https://operation.appliket.com/";
    private const string RetiringCollector = "https://operation.appliket.com/_telemetry/";
    private static readonly HashSet<string> ExpectedFields =
    [
        "version", "adminPublicUrl", "collectorPublicUrl", "compatibilityAdminPublicUrls",
        "compatibilityCollectorPublicUrls", "siteOrigins"
    ];

    private WebsiteAdminCallbackSet(HashSet<Uri> redirects, HashSet<Uri> postLogouts, bool rootProtocol = false, bool rootRecovery = false, bool migrationWindow = false)
    {
        RootProtocol = rootProtocol;
        IsRootRecovery = rootRecovery;
        IsMigrationWindow = migrationWindow;
        RedirectUris = redirects;
        PostLogoutRedirectUris = postLogouts;
    }

    internal bool RootProtocol { get; }
    internal bool IsRootRecovery { get; }
    internal bool IsMigrationWindow { get; }
    internal WebsiteAdminCallbackSet ForRootRecovery()
    {
        if (!RootProtocol || IsRootRecovery || IsMigrationWindow) throw new InvalidOperationException("Root recovery mode was rejected.");
        return new WebsiteAdminCallbackSet(
            new[] { CanonicalAdmin, CompatibilityAdmin }.Select(url => new Uri(new Uri(url), "signin-oidc")).ToHashSet(),
            new[] { CanonicalAdmin, CompatibilityAdmin }.Select(url => new Uri(new Uri(url), "signout-callback-oidc")).ToHashSet(), true, true);
    }
    internal IReadOnlySet<Uri> RedirectUris { get; }
    internal IReadOnlySet<Uri> PostLogoutRedirectUris { get; }

    internal static WebsiteAdminCallbackSet FromEndpoints(JsonElement endpoints)
    {
        try
        {
            if (endpoints.ValueKind != JsonValueKind.Object ||
                endpoints.EnumerateObject().Count() != ExpectedFields.Count ||
                !endpoints.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal).SetEquals(ExpectedFields) ||
                endpoints.GetProperty("version").ValueKind != JsonValueKind.Number ||
                !endpoints.GetProperty("version").TryGetInt32(out var version) || version is not (2 or 3 or 4) ||
                endpoints.GetProperty("adminPublicUrl").GetString() != AdminPublicUrl(version) ||
                endpoints.GetProperty("collectorPublicUrl").GetString() != CollectorPublicUrl(version) ||
                !CompatibilityAdminMatches(endpoints.GetProperty("compatibilityAdminPublicUrls"), version) ||
                !ReadSingleExactUrl(endpoints.GetProperty("compatibilityCollectorPublicUrls"), CompatibilityCollectorPublicUrl(version)) ||
                !HasExactSiteOrigins(endpoints.GetProperty("siteOrigins")))
            {
                throw new InvalidOperationException();
            }

            var urls = AdminPublicUrls(version);
            var admins = urls
                .Select(url => new Uri(new Uri(url, UriKind.Absolute), "signin-oidc")).ToHashSet();
            var logouts = urls
                .Select(url => new Uri(new Uri(url, UriKind.Absolute), "signout-callback-oidc")).ToHashSet();
            if (admins.Count != urls.Length || logouts.Count != admins.Count) throw new InvalidOperationException();
            return new WebsiteAdminCallbackSet(admins, logouts, version >= 3, version == 4);
        }
        catch (Exception exception) when (exception is KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException)
        {
            throw new InvalidOperationException("The Cloud Operation endpoint contract was rejected.");
        }
    }

    private static string AdminPublicUrl(int version) => version switch
    {
        2 => CanonicalAdmin,
        3 => RetiringRoot,
        _ => MigratingRoot
    };
    private static string CollectorPublicUrl(int version) => version == 4 ? MigratingCollector : CanonicalCollector;
    private static bool CompatibilityAdminMatches(JsonElement value, int version) => version switch
    {
        2 => ReadSingleExactUrl(value, CompatibilityAdmin),
        3 => value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0,
        _ => ReadSingleExactUrl(value, RetiringRoot)
    };
    private static string CompatibilityCollectorPublicUrl(int version) => version == 4 ? RetiringCollector : CompatibilityCollector;
    private static string[] AdminPublicUrls(int version) => version switch
    {
        2 => [CanonicalAdmin, CompatibilityAdmin],
        3 => [RetiringRoot],
        _ => [MigratingRoot, RetiringRoot]
    };

    private static bool ReadSingleExactUrl(JsonElement value, string expected)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() != 1) return false;
        var urls = value.EnumerateArray().Select(item => item.GetString()).ToArray();
        return urls.Length == 1 && urls[0] == expected && urls.Distinct(StringComparer.Ordinal).Count() == 1;
    }

    private static bool HasExactSiteOrigins(JsonElement origins) =>
        origins.ValueKind == JsonValueKind.Object && origins.EnumerateObject().Count() == 2 &&
        origins.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal)
            .SetEquals(["cn", "global"]) &&
        origins.GetProperty("cn").GetString() == "https://pandalabs.cn" &&
        origins.GetProperty("global").GetString() == "https://pandalabs.cc";
}
