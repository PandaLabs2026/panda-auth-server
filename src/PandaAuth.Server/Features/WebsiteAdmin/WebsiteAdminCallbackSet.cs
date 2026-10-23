using System.Text.Json;

namespace PandaAuth.Server.Features.WebsiteAdmin;

internal sealed class WebsiteAdminCallbackSet
{
    private const string CanonicalAdmin = "https://operation.appliket.com/operation/";
    private const string CompatibilityAdmin = "https://appliket.com/operation/";
    private const string CanonicalCollector = "https://operation.appliket.com/_telemetry/";
    private const string CompatibilityCollector = "https://appliket.com/_telemetry/";
    private static readonly HashSet<string> ExpectedFields =
    [
        "version", "adminPublicUrl", "collectorPublicUrl", "compatibilityAdminPublicUrls",
        "compatibilityCollectorPublicUrls", "siteOrigins"
    ];

    private WebsiteAdminCallbackSet(HashSet<Uri> redirects, HashSet<Uri> postLogouts, bool rootProtocol = false, bool rootRecovery = false)
    {
        RootProtocol = rootProtocol;
        IsRootRecovery = rootRecovery;
        RedirectUris = redirects;
        PostLogoutRedirectUris = postLogouts;
    }

    internal bool RootProtocol { get; }
    internal bool IsRootRecovery { get; }
    internal WebsiteAdminCallbackSet ForRootRecovery()
    {
        if (!RootProtocol || IsRootRecovery) throw new InvalidOperationException("Root recovery mode was rejected.");
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
                !endpoints.GetProperty("version").TryGetInt32(out var version) || version is not (2 or 3) ||
                endpoints.GetProperty("adminPublicUrl").GetString() != (version == 3 ? "https://operation.appliket.com/" : CanonicalAdmin) ||
                endpoints.GetProperty("collectorPublicUrl").GetString() != CanonicalCollector ||
                !(version == 3 ? endpoints.GetProperty("compatibilityAdminPublicUrls").ValueKind == JsonValueKind.Array && endpoints.GetProperty("compatibilityAdminPublicUrls").GetArrayLength() == 0 : ReadSingleExactUrl(endpoints.GetProperty("compatibilityAdminPublicUrls"), CompatibilityAdmin)) ||
                !ReadSingleExactUrl(endpoints.GetProperty("compatibilityCollectorPublicUrls"), CompatibilityCollector) ||
                !HasExactSiteOrigins(endpoints.GetProperty("siteOrigins")))
            {
                throw new InvalidOperationException();
            }

            var urls = version == 3 ? new[] { "https://operation.appliket.com/" } : new[] { CanonicalAdmin, CompatibilityAdmin };
            var admins = urls
                .Select(url => new Uri(new Uri(url, UriKind.Absolute), "signin-oidc")).ToHashSet();
            var logouts = urls
                .Select(url => new Uri(new Uri(url, UriKind.Absolute), "signout-callback-oidc")).ToHashSet();
            if (admins.Count != (version == 3 ? 1 : 2) || logouts.Count != admins.Count) throw new InvalidOperationException();
            return new WebsiteAdminCallbackSet(admins, logouts, version == 3);
        }
        catch (Exception exception) when (exception is KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException)
        {
            throw new InvalidOperationException("The Cloud Operation endpoint contract was rejected.");
        }
    }

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
