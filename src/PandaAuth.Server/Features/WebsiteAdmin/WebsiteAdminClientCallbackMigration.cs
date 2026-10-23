using OpenIddict.Abstractions;

namespace PandaAuth.Server.Features.WebsiteAdmin;

internal static class WebsiteAdminClientCallbackMigration
{
    private static readonly HashSet<Uri> PreviousOperationRedirectUris =
        [new("https://appliket.com/operation/signin-oidc")];
    private static readonly HashSet<Uri> PreviousOperationLogoutUris =
        [new("https://appliket.com/operation/signout-callback-oidc")];
    private static readonly HashSet<Uri> PreviousAdminAndOperationRedirectUris =
    [
        new("https://appliket.com/admin/signin-oidc"),
        new("https://appliket.com/operation/signin-oidc")
    ];
    private static readonly HashSet<Uri> PreviousAdminAndOperationLogoutUris =
    [
        new("https://appliket.com/admin/signout-callback-oidc"),
        new("https://appliket.com/operation/signout-callback-oidc")
    ];

    private static readonly HashSet<Uri> DualRedirectUris = [new("https://operation.appliket.com/operation/signin-oidc"), new("https://appliket.com/operation/signin-oidc")];
    private static readonly HashSet<Uri> DualLogoutUris = [new("https://operation.appliket.com/operation/signout-callback-oidc"), new("https://appliket.com/operation/signout-callback-oidc")];
    private static readonly HashSet<Uri> RootRedirectUris = [new("https://operation.appliket.com/signin-oidc")];
    private static readonly HashSet<Uri> RootLogoutUris = [new("https://operation.appliket.com/signout-callback-oidc")];

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

        if (target.RootProtocol && (descriptor.ClientId != PandaAuth.Server.Infrastructure.Persistence.FirstPartyClients.CloudOperationWeb ||
            !expectedRedirectUris.SetEquals(target.IsRootRecovery ? RootRedirectUris : DualRedirectUris) ||
            !expectedPostLogoutRedirectUris.SetEquals(target.IsRootRecovery ? RootLogoutUris : DualLogoutUris)))
            throw new InvalidOperationException("The Cloud Operation root callback precondition was rejected.");
        var targetCount = target.RootProtocol && !target.IsRootRecovery ? 1 : 2;
        if (target.RedirectUris.Count != targetCount || target.PostLogoutRedirectUris.Count != targetCount)
            throw new InvalidOperationException("The Cloud Operation callback target was rejected.");

        // Match the command's idempotent retry: only the complete exact target
        // is a no-op. A partially applied or otherwise drifted set still fails.
        if (descriptor.RedirectUris.ToHashSet().SetEquals(target.RedirectUris) &&
            descriptor.PostLogoutRedirectUris.ToHashSet().SetEquals(target.PostLogoutRedirectUris))
            return;

        var knownPreviousState = target.RootProtocol ||
            expectedRedirectUris.SetEquals(PreviousOperationRedirectUris) &&
            expectedPostLogoutRedirectUris.SetEquals(PreviousOperationLogoutUris) ||
            expectedRedirectUris.SetEquals(PreviousAdminAndOperationRedirectUris) &&
            expectedPostLogoutRedirectUris.SetEquals(PreviousAdminAndOperationLogoutUris);
        if (!knownPreviousState ||
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
