using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;

namespace PandaAuth.ReadinessHarness;

/// <summary>Read-only account selection. Caller must establish the approved
/// runtime DB identity and a read-only transaction before invoking this probe.</summary>
internal static class ActivationIdentityPreflight
{
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static void Require(bool value) { if (!value) throw new InvalidOperationException("activation_identity_preflight_failed"); }

    internal static async Task<bool> CheckAsync(PandaAuthDbContext db, string userName, string usernameSha256,
        string subjectSha256, bool expectAdmin, DateTimeOffset now, CancellationToken cancellation = default)
    {
        Require(userName is { Length: > 0 and <= 256 } && userName == userName.Trim() && Hash(userName) == usernameSha256);
        // This is the exact lookup normalization in UserService.FindByNameAsync.
        // Project only the facts needed here; do not load the password hash or
        // TOTP ciphertext into the helper.
        var normalized = userName.Normalize().ToUpperInvariant();
        var matches = await db.Users.AsNoTracking().Where(user => user.NormalizedUserName == normalized)
            .Select(user => new { user.Id, user.UserName, user.Status, user.EmailConfirmed, user.TwoFactorEnabled,
                user.LockoutEnabled, user.LockoutEnd, HasPassword = user.PasswordHash != null && user.PasswordHash != "" })
            .ToListAsync(cancellation);
        Require(matches.Count == 1);
        var user = matches[0];
        Require(user.UserName == userName && Hash(user.Id) == subjectSha256 && user.Status == UserStatus.Active
            && user.EmailConfirmed && user.TwoFactorEnabled && user.HasPassword
            && (!user.LockoutEnabled || user.LockoutEnd is null || user.LockoutEnd <= now));
        var roleNames = await (from membership in db.UserRoles.AsNoTracking()
                             join role in db.Roles.AsNoTracking() on membership.RoleId equals role.Id
                             where membership.UserId == user.Id
                             select role.Name).ToListAsync(cancellation);
        // Claims authorization compares actual role names, not normalized
        // lookup keys or potentially case-insensitive database collation.
        var isAdmin = roleNames.Any(name => string.Equals(name, PandaAuthRoles.Admin, StringComparison.Ordinal));
        Require(isAdmin == expectAdmin);
        var step = now.ToUnixTimeSeconds() / 30;
        var usableFactor = await db.TotpFactors.AsNoTracking().AnyAsync(factor => factor.UserId == user.Id
            && factor.ConfirmedAt != null && factor.RevokedAt == null
            && (factor.LastAcceptedTimeStep == null || factor.LastAcceptedTimeStep <= step), cancellation);
        Require(usableFactor);
        return true;
    }
}
