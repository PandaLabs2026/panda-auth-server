namespace PandaAuth.Server.Infrastructure.Security.External;

/// <summary>
/// Adapter boundary for a provider-verified external identity. Implementations must
/// validate the provider callback before returning a stable subject; no provider token
/// crosses this boundary or is persisted by PandaAuth.
/// </summary>
public interface IExternalIdentityProvider
{
    string Provider { get; }

    Task<ExternalIdentityProfile> ResolveVerifiedIdentityAsync(
        ExternalIdentityProviderContext context,
        CancellationToken cancellationToken = default);
}

/// <summary>Provider-neutral callback input. Adapters validate state/signature/expiry before returning a profile.</summary>
public sealed record ExternalIdentityProviderContext(
    string Provider,
    IReadOnlyDictionary<string, string> Parameters,
    Uri? RedirectUri = null);
