using OpenIddict.Abstractions;

namespace PandaAuth.Server.Features.WebsiteAdmin;

internal static class WebsiteAdminClientCallbackMigration
{
    internal static void Apply(
        OpenIddictApplicationDescriptor descriptor,
        IReadOnlySet<Uri> expectedRedirectUris,
        IReadOnlySet<Uri> expectedPostLogoutRedirectUris,
        WebsiteAdminCallbackSet target)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(expectedRedirectUris);
        ArgumentNullException.ThrowIfNull(expectedPostLogoutRedirectUris);
        ArgumentNullException.ThrowIfNull(target);

        if (target.RedirectUris.Count != 2 || target.PostLogoutRedirectUris.Count != 2)
            throw new InvalidOperationException("The Cloud Operation callback target was rejected.");

        // Match the command's idempotent retry: only the complete exact target
        // is a no-op. A partially applied or otherwise drifted set still fails.
        if (descriptor.RedirectUris.ToHashSet().SetEquals(target.RedirectUris) &&
            descriptor.PostLogoutRedirectUris.ToHashSet().SetEquals(target.PostLogoutRedirectUris))
            return;

        if (expectedRedirectUris.Count != 1 || expectedPostLogoutRedirectUris.Count != 1 ||
            !descriptor.RedirectUris.ToHashSet().SetEquals(expectedRedirectUris) ||
            !descriptor.PostLogoutRedirectUris.ToHashSet().SetEquals(expectedPostLogoutRedirectUris))
        {
            throw new InvalidOperationException("The Cloud Operation callback state changed; migration was rejected.");
        }

        descriptor.RedirectUris.Clear();
        descriptor.RedirectUris.UnionWith(target.RedirectUris);
        descriptor.PostLogoutRedirectUris.Clear();
        descriptor.PostLogoutRedirectUris.UnionWith(target.PostLogoutRedirectUris);
    }
}
