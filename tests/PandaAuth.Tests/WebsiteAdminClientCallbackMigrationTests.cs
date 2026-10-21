using OpenIddict.Abstractions;
using PandaAuth.Server.Features.WebsiteAdmin;
using Xunit;

namespace PandaAuth.Tests;

public sealed class WebsiteAdminClientCallbackMigrationTests
{
    private static WebsiteAdminCallbackSet Target()
    {
        using var endpoints = System.Text.Json.JsonDocument.Parse("""
            {"version":2,"adminPublicUrl":"https://operation.appliket.com/operation/","collectorPublicUrl":"https://operation.appliket.com/_telemetry/","compatibilityAdminPublicUrls":["https://appliket.com/operation/"],"compatibilityCollectorPublicUrls":["https://appliket.com/_telemetry/"],"siteOrigins":{"cn":"https://pandalabs.cn","global":"https://pandalabs.cc"}}
            """);
        return WebsiteAdminCallbackSet.FromEndpoints(endpoints.RootElement);
    }

    [Fact]
    public void Changes_only_callback_sets_after_exact_precondition_match()
    {
        var beforeRedirects = new HashSet<Uri> { new("https://appliket.com/operation/signin-oidc") };
        var beforeLogouts = new HashSet<Uri> { new("https://appliket.com/operation/signout-callback-oidc") };
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "cloud-operation-web",
            ClientSecret = "retained-secret-value",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            DisplayName = "Cloud Operation",
            RedirectUris = { new Uri("https://appliket.com/operation/signin-oidc") },
            PostLogoutRedirectUris = { new Uri("https://appliket.com/operation/signout-callback-oidc") },
            Permissions = { OpenIddictConstants.Permissions.Endpoints.Authorization, OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode },
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
        };
        var original = Snapshot(descriptor);

        WebsiteAdminClientCallbackMigration.Apply(descriptor, beforeRedirects, beforeLogouts, Target());

        Assert.Equal(new[]
        {
            new Uri("https://operation.appliket.com/operation/signin-oidc"),
            new Uri("https://appliket.com/operation/signin-oidc")
        }.OrderBy(uri => uri.Host), descriptor.RedirectUris.OrderBy(uri => uri.Host));
        Assert.Equal(new[]
        {
            new Uri("https://operation.appliket.com/operation/signout-callback-oidc"),
            new Uri("https://appliket.com/operation/signout-callback-oidc")
        }.OrderBy(uri => uri.Host), descriptor.PostLogoutRedirectUris.OrderBy(uri => uri.Host));
        Assert.Equal(original with
        {
            RedirectUris = JoinUris(descriptor.RedirectUris),
            PostLogoutRedirectUris = JoinUris(descriptor.PostLogoutRedirectUris)
        }, Snapshot(descriptor));
    }

    [Fact]
    public void Replaces_the_exact_live_legacy_admin_and_operation_callback_sets()
    {
        var beforeRedirects = new HashSet<Uri>
        {
            new("https://appliket.com/admin/signin-oidc"),
            new("https://appliket.com/operation/signin-oidc")
        };
        var beforeLogouts = new HashSet<Uri>
        {
            new("https://appliket.com/admin/signout-callback-oidc"),
            new("https://appliket.com/operation/signout-callback-oidc")
        };
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "cloud-operation-web",
            ClientSecret = "retained-secret-value",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "PandaLabs 运维观测面"
        };
        descriptor.RedirectUris.UnionWith(beforeRedirects);
        descriptor.PostLogoutRedirectUris.UnionWith(beforeLogouts);
        var original = Snapshot(descriptor);

        WebsiteAdminClientCallbackMigration.Apply(descriptor, beforeRedirects, beforeLogouts, Target());

        var target = Target();
        Assert.Equal(target.RedirectUris.OrderBy(uri => uri.Host), descriptor.RedirectUris.OrderBy(uri => uri.Host));
        Assert.Equal(target.PostLogoutRedirectUris.OrderBy(uri => uri.Host), descriptor.PostLogoutRedirectUris.OrderBy(uri => uri.Host));
        Assert.Equal(original with
        {
            RedirectUris = JoinUris(descriptor.RedirectUris),
            PostLogoutRedirectUris = JoinUris(descriptor.PostLogoutRedirectUris)
        }, Snapshot(descriptor));
    }

    [Fact]
    public void Already_at_target_is_a_noop_even_with_original_preconditions()
    {
        var target = Target();
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "cloud-operation-web",
            ClientSecret = "retained-secret-value",
            DisplayName = "Retained display",
            Permissions = { OpenIddictConstants.Permissions.Endpoints.Authorization },
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
        };
        descriptor.RedirectUris.UnionWith(target.RedirectUris);
        descriptor.PostLogoutRedirectUris.UnionWith(target.PostLogoutRedirectUris);
        var original = Snapshot(descriptor);

        WebsiteAdminClientCallbackMigration.Apply(descriptor,
            new HashSet<Uri> { new("https://appliket.com/operation/signin-oidc") },
            new HashSet<Uri> { new("https://appliket.com/operation/signout-callback-oidc") }, target);

        Assert.Equal(original, Snapshot(descriptor));
    }

    [Fact]
    public void Partial_target_is_not_treated_as_a_completed_migration()
    {
        var target = Target();
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "cloud-operation-web",
            PostLogoutRedirectUris = { new Uri("https://appliket.com/operation/signout-callback-oidc") }
        };
        descriptor.RedirectUris.UnionWith(target.RedirectUris);
        var original = Snapshot(descriptor);

        Assert.Throws<InvalidOperationException>(() => WebsiteAdminClientCallbackMigration.Apply(descriptor,
            new HashSet<Uri> { new("https://appliket.com/operation/signin-oidc") },
            new HashSet<Uri> { new("https://appliket.com/operation/signout-callback-oidc") }, target));

        Assert.Equal(original, Snapshot(descriptor));
    }

    [Fact]
    public void Callback_set_drift_fails_without_mutating_the_descriptor()
    {
        var expectedRedirects = new HashSet<Uri> { new("https://appliket.com/operation/signin-oidc") };
        var expectedLogouts = new HashSet<Uri> { new("https://appliket.com/operation/signout-callback-oidc") };
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "cloud-operation-web",
            ClientSecret = "retained-secret-value",
            RedirectUris = { new Uri("https://other.appliket.com/operation/signin-oidc") },
            PostLogoutRedirectUris = { new Uri("https://appliket.com/operation/signout-callback-oidc") }
        };
        var original = Snapshot(descriptor);

        Assert.Throws<InvalidOperationException>(() => WebsiteAdminClientCallbackMigration.Apply(
            descriptor, expectedRedirects, expectedLogouts, Target()));

        Assert.Equal(original, Snapshot(descriptor));
    }

    [Fact]
    public void Unregistered_callback_in_the_exact_precondition_fails_without_mutation()
    {
        var unexpected = new Uri("https://other.appliket.com/operation/signin-oidc");
        var expectedRedirects = new HashSet<Uri>
        {
            new("https://appliket.com/admin/signin-oidc"),
            new("https://appliket.com/operation/signin-oidc"),
            unexpected
        };
        var expectedLogouts = new HashSet<Uri>
        {
            new("https://appliket.com/admin/signout-callback-oidc"),
            new("https://appliket.com/operation/signout-callback-oidc")
        };
        var descriptor = new OpenIddictApplicationDescriptor
        {
            RedirectUris = { new("https://appliket.com/admin/signin-oidc"),
                new("https://appliket.com/operation/signin-oidc"), unexpected },
            PostLogoutRedirectUris = { new("https://appliket.com/admin/signout-callback-oidc"),
                new("https://appliket.com/operation/signout-callback-oidc") }
        };
        var original = Snapshot(descriptor);

        Assert.Throws<InvalidOperationException>(() => WebsiteAdminClientCallbackMigration.Apply(
            descriptor, expectedRedirects, expectedLogouts, Target()));

        Assert.Equal(original, Snapshot(descriptor));
    }

    private static DescriptorSnapshot Snapshot(OpenIddictApplicationDescriptor descriptor) => new(
        descriptor.ClientId,
        descriptor.ClientSecret,
        descriptor.ClientType,
        descriptor.ConsentType,
        descriptor.DisplayName,
        JoinUris(descriptor.RedirectUris),
        JoinUris(descriptor.PostLogoutRedirectUris),
        string.Join('\n', descriptor.Permissions.Order(StringComparer.Ordinal)),
        string.Join('\n', descriptor.Requirements.Order(StringComparer.Ordinal)));

    private static string JoinUris(IEnumerable<Uri> uris) =>
        string.Join('\n', uris.Select(uri => uri.AbsoluteUri).Order(StringComparer.Ordinal));

    private sealed record DescriptorSnapshot(
        string? ClientId,
        string? ClientSecret,
        string? ClientType,
        string? ConsentType,
        string? DisplayName,
        string RedirectUris,
        string PostLogoutRedirectUris,
        string Permissions,
        string Requirements);
}
