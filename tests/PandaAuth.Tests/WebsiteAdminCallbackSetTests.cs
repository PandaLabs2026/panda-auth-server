using System.Text.Json;
using PandaAuth.Server.Features.WebsiteAdmin;
using Xunit;

namespace PandaAuth.Tests;

public sealed class WebsiteAdminCallbackSetTests
{
    private static JsonDocument Endpoints(
        int version = 2,
        string admin = "https://operation.appliket.com/operation/",
        string compatibilityAdmin = "https://appliket.com/operation/",
        string collector = "https://operation.appliket.com/_telemetry/",
        string compatibilityCollector = "https://appliket.com/_telemetry/") => JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            version,
            adminPublicUrl = admin,
            collectorPublicUrl = collector,
            compatibilityAdminPublicUrls = new[] { compatibilityAdmin },
            compatibilityCollectorPublicUrls = new[] { compatibilityCollector },
            siteOrigins = new { cn = "https://pandalabs.cn", global = "https://pandalabs.cc" }
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

    [Fact]
    public void Derives_exact_canonical_and_compatibility_callback_pairs()
    {
        using var endpoints = Endpoints();

        var callbacks = WebsiteAdminCallbackSet.FromEndpoints(endpoints.RootElement);

        Assert.Equal(new[]
        {
            new Uri("https://operation.appliket.com/operation/signin-oidc"),
            new Uri("https://appliket.com/operation/signin-oidc")
        }.OrderBy(uri => uri.Host), callbacks.RedirectUris.OrderBy(uri => uri.Host));
        Assert.Equal(new[]
        {
            new Uri("https://operation.appliket.com/operation/signout-callback-oidc"),
            new Uri("https://appliket.com/operation/signout-callback-oidc")
        }.OrderBy(uri => uri.Host), callbacks.PostLogoutRedirectUris.OrderBy(uri => uri.Host));
    }

    [Theory]
    [InlineData(1, "https://operation.appliket.com/operation/", "https://appliket.com/operation/", "https://operation.appliket.com/_telemetry/", "https://appliket.com/_telemetry/")]
    [InlineData(2, "http://operation.appliket.com/operation/", "https://appliket.com/operation/", "https://operation.appliket.com/_telemetry/", "https://appliket.com/_telemetry/")]
    [InlineData(2, "https://user@operation.appliket.com/operation/", "https://appliket.com/operation/", "https://operation.appliket.com/_telemetry/", "https://appliket.com/_telemetry/")]
    [InlineData(2, "https://operation.appliket.com/operation/?x=1", "https://appliket.com/operation/", "https://operation.appliket.com/_telemetry/", "https://appliket.com/_telemetry/")]
    [InlineData(2, "https://*.appliket.com/operation/", "https://appliket.com/operation/", "https://operation.appliket.com/_telemetry/", "https://appliket.com/_telemetry/")]
    [InlineData(2, "https://evil.example/operation/", "https://appliket.com/operation/", "https://operation.appliket.com/_telemetry/", "https://appliket.com/_telemetry/")]
    [InlineData(2, "https://operation.appliket.com/operation/", "https://appliket.com/other/", "https://operation.appliket.com/_telemetry/", "https://appliket.com/_telemetry/")]
    public void Rejects_wrong_version_and_unregistered_or_malformed_endpoints(
        int version, string admin, string compatibilityAdmin, string collector, string compatibilityCollector)
    {
        using var endpoints = Endpoints(version, admin, compatibilityAdmin, collector, compatibilityCollector);

        Assert.Throws<InvalidOperationException>(() => WebsiteAdminCallbackSet.FromEndpoints(endpoints.RootElement));
    }

    [Theory]
    [InlineData("https://operation.appliket.com/?x=1")]
    [InlineData("https://operation.appliket.com/#fragment")]
    [InlineData("https://operation.appliket.com:444/")]
    [InlineData("https://user@operation.appliket.com/")]
    [InlineData("https://other.appliket.com/")]
    [InlineData("https://operation.appliket.com/operation/")]
    public void Root_v3_rejects_every_non_exact_management_url(string url)
    {
        using var endpoints = JsonDocument.Parse(JsonSerializer.Serialize(new { version = 3, adminPublicUrl = url, collectorPublicUrl = "https://operation.appliket.com/_telemetry/", compatibilityAdminPublicUrls = Array.Empty<string>(), compatibilityCollectorPublicUrls = new[] { "https://appliket.com/_telemetry/" }, siteOrigins = new { cn = "https://pandalabs.cn", global = "https://pandalabs.cc" } }));
        Assert.Throws<InvalidOperationException>(() => WebsiteAdminCallbackSet.FromEndpoints(endpoints.RootElement));
    }

    [Fact]
    public void Root_v3_rejects_compatibility_aliases_and_duplicate_fields()
    {
        const string root = """
            {"version":3,"adminPublicUrl":"https://operation.appliket.com/","collectorPublicUrl":"https://operation.appliket.com/_telemetry/","compatibilityAdminPublicUrls":[],"compatibilityCollectorPublicUrls":["https://appliket.com/_telemetry/"],"siteOrigins":{"cn":"https://pandalabs.cn","global":"https://pandalabs.cc"}}
            """;
        foreach (var invalid in new[] { root.Replace("\"compatibilityAdminPublicUrls\":[]", "\"compatibilityAdminPublicUrls\":[\"https://appliket.com/operation/\"]"), root.Replace("\"version\":3", "\"version\":3,\"version\":3") })
        {
            using var endpoints = JsonDocument.Parse(invalid);
            Assert.Throws<InvalidOperationException>(() => WebsiteAdminCallbackSet.FromEndpoints(endpoints.RootElement));
        }
        using var historical = Endpoints();
        Assert.Throws<InvalidOperationException>(() => WebsiteAdminCallbackSet.FromEndpoints(historical.RootElement).ForRootRecovery());
    }

    [Fact]
    public void Rejects_duplicate_compatibility_urls()
    {
        using var endpoints = JsonDocument.Parse("""
            {"version":2,"adminPublicUrl":"https://operation.appliket.com/operation/","collectorPublicUrl":"https://operation.appliket.com/_telemetry/","compatibilityAdminPublicUrls":["https://appliket.com/operation/","https://appliket.com/operation/"],"compatibilityCollectorPublicUrls":["https://appliket.com/_telemetry/"],"siteOrigins":{"cn":"https://pandalabs.cn","global":"https://pandalabs.cc"}}
            """);

        Assert.Throws<InvalidOperationException>(() => WebsiteAdminCallbackSet.FromEndpoints(endpoints.RootElement));
    }
}
