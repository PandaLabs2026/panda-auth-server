using System.Security.Claims;
using OpenIddict.Abstractions;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.SessionState;

internal static class SessionStateAuthorization
{
    public const string PolicyName = "session-state-revocation";

    public static bool HasAudienceAndScope(ClaimsPrincipal principal)
        => (principal.GetAudiences().Contains(PandaAuthSessionApi.Audience, StringComparer.Ordinal)
            || principal.FindAll(OpenIddictConstants.Claims.Audience)
                .Any(claim => string.Equals(claim.Value, PandaAuthSessionApi.Audience, StringComparison.Ordinal)))
           && (principal.HasScope(PandaAuthSessionApi.Scope)
               || principal.FindAll(OpenIddictConstants.Claims.Scope)
                   .Any(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                       .Contains(PandaAuthSessionApi.Scope, StringComparer.Ordinal)));
}
