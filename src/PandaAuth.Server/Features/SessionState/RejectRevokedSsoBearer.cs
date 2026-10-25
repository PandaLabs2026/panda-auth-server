using OpenIddict.Abstractions;
using System.Security.Claims;
using OpenIddict.Validation;
using PandaAuth.Shared;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Features.SessionState;

public sealed class RejectRevokedSsoBearer(SessionRevocationService revocations, UserService users)
    : IOpenIddictValidationHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    public async ValueTask HandleAsync(OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        var ids = context.AccessTokenPrincipal?.FindAll(PandaAuthClaims.SsoSessionId).ToArray() ?? [];
        var kinds = context.AccessTokenPrincipal?.FindAll(PandaAuthClaims.SubjectType).ToArray() ?? [];
        if (context.AccessTokenPrincipal is null || (ids.Length == 0 && kinds.Length == 1 && kinds[0].Value == PandaAuthClaims.SubjectTypes.Machine)) return;
        if (!await AccountSecurityVersion.IsCurrentAsync(context.AccessTokenPrincipal, users)
            || ids.Length != 1 || !Guid.TryParseExact(ids[0].Value, "N", out _)
            || await revocations.IsRevokedAsync(PandaAuthSessionApi.SsoPartition, ids[0].Value, context.CancellationToken))
            context.Reject(error: OpenIddictConstants.Errors.InvalidToken);
    }
}
