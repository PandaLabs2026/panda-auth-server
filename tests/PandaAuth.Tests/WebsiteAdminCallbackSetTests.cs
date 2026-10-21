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

    [Fact]
    public void Rejects_duplicate_compatibility_urls()
    {
        using var endpoints = JsonDocument.Parse("""
            {"version":2,"adminPublicUrl":"https://operation.appliket.com/operation/","collectorPublicUrl":"https://operation.appliket.com/_telemetry/","compatibilityAdminPublicUrls":["https://appliket.com/operation/","https://appliket.com/operation/"],"compatibilityCollectorPublicUrls":["https://appliket.com/_telemetry/"],"siteOrigins":{"cn":"https://pandalabs.cn","global":"https://pandalabs.cc"}}
            """);

        Assert.Throws<InvalidOperationException>(() => WebsiteAdminCallbackSet.FromEndpoints(endpoints.RootElement));
    }
}
