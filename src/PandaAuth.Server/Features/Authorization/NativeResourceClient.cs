using System.Security.Claims;
using OpenIddict.Abstractions;
using PandaAuth.Server.Infrastructure.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Authorization;

internal sealed record NativeResourceClient(string ClientId, string Revision, string Issuer, NativeLoginRoute.ApiResource Resource)
{
    internal const string SectionName = "Auth:NativeLogin:ResourceAccess";
    internal const string RevisionClaim = "urn:pandaauth:internal:native-resource-revision";

    internal static NativeResourceClient? Read(IConfiguration configuration, string primaryClientId,
        NativeLoginRoute.ApiResource? resource)
    {
        var section = configuration.GetSection(SectionName);
        if (section["Enabled"] is null && section["ClientId"] is null && section["Revision"] is null)
            return null;

        var clientId = section["ClientId"];
        var revision = section["Revision"];
        if (resource is null || !bool.TryParse(section["Enabled"], out _)
            || string.IsNullOrEmpty(clientId) || clientId.Length > BusinessInputLimits.ClientId || clientId == primaryClientId
            || clientId.Any(character => char.IsWhiteSpace(character) || char.IsControl(character))
            || !Guid.TryParseExact(revision, "D", out var parsedRevision) || parsedRevision == Guid.Empty)
            throw new InvalidOperationException("A dedicated native resource requires a separate client and a registration revision.");

        return new NativeResourceClient(clientId, revision!, configuration["Auth:Issuer"]!, resource);
    }

    internal static bool IsConfiguredClient(IConfiguration? configuration, string? clientId)
        => !string.IsNullOrEmpty(clientId) && clientId == configuration?[$"{SectionName}:ClientId"];

    internal bool IsCurrent(IConfiguration configuration)
        => IsEnabled(configuration) && IsConfiguredClient(configuration, ClientId)
            && configuration[$"{SectionName}:Revision"] == Revision && configuration["Auth:Issuer"] == Issuer
            && configuration[$"{SectionName}:Scope"] == Resource.Scope
            && Resource.Audiences.SetEquals(configuration.GetSection($"{SectionName}:Audiences").Get<string[]>() ?? []);

    private static bool IsEnabled(IConfiguration configuration)
        => string.Equals(configuration[$"{SectionName}:Enabled"], "true", StringComparison.OrdinalIgnoreCase)
            && string.Equals(configuration["Auth:NativeLogin:Enabled"], "true", StringComparison.OrdinalIgnoreCase)
            && string.Equals(configuration[$"{NativeLoginRoute.PilotConfig}:Enabled"], "true", StringComparison.OrdinalIgnoreCase)
            && configuration["Auth:Issuer"] == NativeLoginRoute.PilotIssuer;

    internal bool Allows(ClaimsPrincipal principal)
        => principal.HasScope(Resource.Scope) && !Resource.HasInvalidAudience(principal)
            && principal.GetScopes().All(scope => scope == Scopes.OpenId || scope == Resource.Scope);

    internal void Mark(ClaimsPrincipal principal)
        => ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(RevisionClaim, Revision).SetDestinations(Destinations.AccessToken));

    internal static bool RejectInactivePrincipal(ClaimsPrincipal principal, IConfiguration configuration)
    {
        var revisions = principal.FindAll(RevisionClaim).ToArray();
        var client = configuration[$"{SectionName}:ClientId"];
        var scope = configuration[$"{SectionName}:Scope"];
        if (revisions.Length == 0
            && (string.IsNullOrEmpty(client) || (!principal.GetPresenters().Contains(client, StringComparer.Ordinal)
                && (string.IsNullOrEmpty(scope) || !principal.HasScope(scope)))))
            return false;

        if (revisions.Length != 1 || !IsEnabled(configuration) || string.IsNullOrEmpty(client)
            || !principal.GetPresenters().SequenceEqual([client])
            || revisions[0].Value != configuration[$"{SectionName}:Revision"]
            || string.IsNullOrEmpty(scope) || !principal.HasScope(scope)
            || principal.GetScopes().Any(grant => grant != Scopes.OpenId && grant != scope))
            return true;

        try
        {
            // OpenIddict moves resources to audiences when minting an access token.
            var resourceClaims = principal.HasTokenType(TokenTypeIdentifiers.AccessToken)
                ? principal.GetAudiences() : principal.GetResources();
            return NativeLoginRoute.ReadResourceAccess(configuration) is not { } resource
                || !resource.Audiences.SetEquals(resourceClaims);
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }
}
