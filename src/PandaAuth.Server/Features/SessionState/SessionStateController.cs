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
public sealed class SessionStateController(SessionRevocationService revocations, IConfiguration? configuration = null) : ControllerBase
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

    [HttpPost("sso/check")]
    public async Task<ActionResult<SessionStateCheckResponse>> CheckSso(
        [FromBody] SessionStateCheckRequest? request, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (!TryGetClientId(out _)) return Forbid();
        if (!TryGetSsoId(request?.SessionId, out var sid)) return BadRequest();
        return Ok(new SessionStateCheckResponse(await revocations.IsRevokedAsync(
            PandaAuthSessionApi.SsoPartition, sid, cancellationToken)));
    }

    [HttpPost("sso/revoke")]
    public async Task<IActionResult> RevokeSso(
        [FromBody] SessionStateRevokeRequest? request, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (!TryGetClientId(out _)) return Forbid();
        if (!TryGetSsoId(request?.SessionId, out var sid)) return BadRequest();
        if (configuration?.GetValue<bool>(PandaAuthSessionApi.SharedLogoutEnabled) != true)
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        await revocations.RevokeAsync(PandaAuthSessionApi.SsoPartition, sid, cancellationToken);
        return NoContent();
    }

    private static bool TryGetSsoId(string? value, out string sid)
    {
        sid = value ?? string.Empty;
        return Guid.TryParseExact(sid, "N", out _);
    }

    private static bool TryGetSessionId(string? value, out string sessionId)
    {
        sessionId = value ?? string.Empty;
        return !string.IsNullOrWhiteSpace(sessionId) && sessionId.Length <= 256;
    }
}
