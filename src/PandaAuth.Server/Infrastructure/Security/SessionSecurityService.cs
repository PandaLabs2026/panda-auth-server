using System.Security.Claims;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed class SessionSecurityService(
    UserService users,
    ITokenRevoker tokenRevoker,
    SecurityEventWriter? securityEvents = null)
{
    /// <summary>Returns the active account only when the cookie's security stamp is current.</summary>
    public async Task<PandaUser?> RequireCurrentUserAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? principal.FindFirstValue("sub");
        var stamp = principal.FindFirstValue(LoginSessionService.StampClaim);
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(stamp)) return null;

        var user = await users.FindByIdAsync(userId);
        return user is { Status: UserStatus.Active } &&
               string.Equals(user.SecurityStamp, stamp, StringComparison.Ordinal)
            ? user
            : null;
    }

    /// <summary>
    /// Rotates the cookie security stamp and revokes online tokens for one security event.
    /// Offline access tokens are intentionally outside this immediate invalidation boundary.
    /// </summary>
    public async Task<AccountResult> InvalidateUserAsync(
        PandaUser user,
        string reason,
        string? actorUserId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        var result = await users.UpdateSecurityStampAsync(user);
        if (!result.Succeeded) return result;

        await tokenRevoker.RevokeUserTokensAsync(user.Id, cancellationToken: cancellationToken);
        if (securityEvents is not null)
        {
            await securityEvents.RecordAsync(new SecurityEventEntry(
                "session.invalidated",
                user.Id,
                actorUserId,
                "user",
                user.Id,
                "system_session_security",
                new { reason },
                null,
                null,
                null), cancellationToken);
        }

        return AccountResult.Success;
    }

    /// <summary>Revokes OpenIddict authorizations/tokens through the existing token boundary.</summary>
    public Task RevokeUserAuthorizationsAsync(
        string userId,
        string? clientId = null,
        CancellationToken cancellationToken = default)
        => tokenRevoker.RevokeUserTokensAsync(userId, clientId, cancellationToken);
}
