using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.SessionState;

[ApiController]
[Route(PandaAuthSessionApi.Prefix)]
[Authorize(
    AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
    Policy = SessionStateAuthorization.PolicyName)]
public sealed class SessionStateController(SessionRevocationService revocations) : ControllerBase
{
    [HttpPost("check")]
    public async Task<ActionResult<SessionStateCheckResponse>> Check(
        [FromBody] SessionStateCheckRequest? request,
        CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (!TryGetSessionId(request?.SessionId, out var sessionId)) return BadRequest();
        if (!TryGetClientId(out var clientId)) return Forbid();

        var revoked = await revocations.IsRevokedAsync(clientId, sessionId, cancellationToken);
        return Ok(new SessionStateCheckResponse(revoked));
    }

    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke(
        [FromBody] SessionStateRevokeRequest? request,
        CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (!TryGetSessionId(request?.SessionId, out var sessionId)) return BadRequest();
        if (!TryGetClientId(out var clientId)) return Forbid();

        await revocations.RevokeAsync(clientId, sessionId, cancellationToken);
        return NoContent();
    }

    private bool TryGetClientId(out string clientId)
    {
        clientId = User.FindFirst(OpenIddict.Abstractions.OpenIddictConstants.Claims.ClientId)?.Value ?? string.Empty;
        return clientId is PandaAuthSessionApi.AdminClientId or PandaAuthSessionApi.MeClientId;
    }

    private static bool TryGetSessionId(string? value, out string sessionId)
    {
        sessionId = value ?? string.Empty;
        return !string.IsNullOrWhiteSpace(sessionId) && sessionId.Length <= 256;
    }
}
