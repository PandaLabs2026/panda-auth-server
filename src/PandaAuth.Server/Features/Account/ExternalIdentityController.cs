using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Features.Account;

/// <summary>
/// Lists and unlinks already-associated identities. Provider callbacks are deliberately
/// not accepted here: only a future verified provider adapter may call BindVerifiedAsync.
/// </summary>
[Authorize]
[RequireConfirmedEmail]
[Route("~/account/external-identities")]
public sealed class ExternalIdentityController(
    ExternalIdentityService identities,
    SessionSecurityService sessions) : Controller
{
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken cancellationToken)
    {
        var user = await sessions.RequireCurrentUserAsync(User, cancellationToken);
        if (user is null) return Challenge();

        var items = await identities.ListActiveAsync(user.Id, cancellationToken);
        return Ok(items.Select(item => new ExternalIdentitySummary(
            item.Id, item.Provider, item.DisplayName, item.EmailSnapshot,
            item.LinkedAt, item.LastUsedAt)).ToArray());
    }

    [HttpPost("{identityId:long}/unlink")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Unlink(long identityId, CancellationToken cancellationToken)
    {
        var user = await sessions.RequireCurrentUserAsync(User, cancellationToken);
        if (user is null) return Challenge();
        if (!SessionSecurityService.HasRecentAuthentication(
                User, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(10)))
        {
            return Forbid();
        }

        var result = await identities.UnbindAsync(user.Id, identityId, cancellationToken);
        if (result.Succeeded) return Ok(new { status = "ok" });
        return result.ErrorCode == "LastLoginMethod"
            ? Conflict(new { error = result.Error })
            : NotFound(new { error = result.Error });
    }
}

public sealed record ExternalIdentitySummary(
    long Id,
    string Provider,
    string? DisplayName,
    string? EmailSnapshot,
    DateTimeOffset LinkedAt,
    DateTimeOffset? LastUsedAt);
