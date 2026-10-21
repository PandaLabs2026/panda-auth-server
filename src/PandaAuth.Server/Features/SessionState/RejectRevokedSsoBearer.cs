using OpenIddict.Abstractions;
using System.Security.Claims;
using OpenIddict.Validation;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.SessionState;

public sealed class RejectRevokedSsoBearer(SessionRevocationService revocations)
    : IOpenIddictValidationHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    public async ValueTask HandleAsync(OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        var ids = context.AccessTokenPrincipal?.FindAll(PandaAuthClaims.SsoSessionId).ToArray() ?? [];
        if (context.AccessTokenPrincipal is null || (ids.Length == 0 && context.AccessTokenPrincipal.FindFirstValue(PandaAuthClaims.SubjectType) == PandaAuthClaims.SubjectTypes.Machine)) return;
        if (ids.Length != 1 || !Guid.TryParseExact(ids[0].Value, "N", out _)
            || await revocations.IsRevokedAsync(PandaAuthSessionApi.SsoPartition, ids[0].Value, context.CancellationToken))
            context.Reject(error: OpenIddictConstants.Errors.InvalidToken);
    }
}
