using System.Security.Claims;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.SessionState;

/// <summary>Checks validated bearer/code/refresh/introspection identities, never an unverified request field.</summary>
public sealed class RejectRevokedSsoSession(SessionRevocationService revocations)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessAuthenticationContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessAuthenticationContext context)
    {
        // ID-token hints are intentionally excluded: end-session must still finish after revocation.
        ClaimsPrincipal?[] principals = [context.AccessTokenPrincipal, context.AuthorizationCodePrincipal,
            context.RefreshTokenPrincipal, context.GenericTokenPrincipal];
        foreach (var principal in principals)
        {
            var ids = principal?.FindAll(PandaAuthClaims.SsoSessionId).ToArray() ?? [];
            var kinds = principal?.FindAll(PandaAuthClaims.SubjectType).ToArray() ?? [];
            if (principal is null || (ids.Length == 0 && kinds.Length == 1 && kinds[0].Value == PandaAuthClaims.SubjectTypes.Machine))
                continue; // Machine identities have no browser login session.
            if (ids.Length != 1 || !Guid.TryParseExact(ids[0].Value, "N", out _)
                || await revocations.IsRevokedAsync(PandaAuthSessionApi.SsoPartition, ids[0].Value, context.CancellationToken))
            {
                context.Reject(error: context.Request?.IsRefreshTokenGrantType() == true
                    ? OpenIddictConstants.Errors.InvalidGrant : OpenIddictConstants.Errors.InvalidToken);
                return;
            }
        }
    }
}
