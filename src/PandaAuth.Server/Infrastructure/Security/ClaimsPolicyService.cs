using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed class ClaimsPolicyService(PandaAuthDbContext db)
{
    private static readonly HashSet<string> Reserved =
    [
        "sub", "role", "amr", "panda_mfa_at", LoginSessionService.StampClaim,
        ClaimTypes.NameIdentifier, ClaimTypes.Name, ClaimTypes.Email,
    ];

    public async Task<AccountResult> AddUserClaimAsync(
        string userId, string claimType, string claimValue, string scope)
    {
        var validation = Validate(claimType, claimValue, scope);
        if (!validation.Succeeded) return validation;
        if (!await db.Users.AnyAsync(user => user.Id == userId))
            return AccountResult.Fail("UserNotFound", "User does not exist.");
        if (await db.UserClaims.AnyAsync(claim => claim.UserId == userId &&
            claim.ClaimType == claimType && claim.ClaimValue == claimValue && claim.Scope == scope))
            return AccountResult.Fail("DuplicateClaim", "Claim already exists.");

        db.UserClaims.Add(new PandaUserClaim
        {
            UserId = userId, ClaimType = claimType, ClaimValue = claimValue, Scope = scope,
        });
        await db.SaveChangesAsync();
        return AccountResult.Success;
    }

    public async Task<AccountResult> AddRoleClaimAsync(
        string roleId, string claimType, string claimValue, string scope)
    {
        var validation = Validate(claimType, claimValue, scope);
        if (!validation.Succeeded) return validation;
        if (!await db.Roles.AnyAsync(role => role.Id == roleId))
            return AccountResult.Fail("RoleNotFound", "Role does not exist.");
        if (await db.RoleClaims.AnyAsync(claim => claim.RoleId == roleId &&
            claim.ClaimType == claimType && claim.ClaimValue == claimValue && claim.Scope == scope))
            return AccountResult.Fail("DuplicateClaim", "Claim already exists.");

        db.RoleClaims.Add(new PandaRoleClaim
        {
            RoleId = roleId, ClaimType = claimType, ClaimValue = claimValue, Scope = scope,
        });
        await db.SaveChangesAsync();
        return AccountResult.Success;
    }

    public async Task<IReadOnlyList<Claim>> GetClaimsAsync(PandaUser user, IReadOnlySet<string> scopes)
    {
        var userClaims = await db.UserClaims
            .Where(claim => claim.UserId == user.Id && scopes.Contains(claim.Scope))
            .Select(claim => new { claim.ClaimType, claim.ClaimValue })
            .ToListAsync();

        var roleClaims = await (from membership in db.UserRoles
                                join claim in db.RoleClaims on membership.RoleId equals claim.RoleId
                                where membership.UserId == user.Id && scopes.Contains(claim.Scope)
                                select new { claim.ClaimType, claim.ClaimValue })
            .ToListAsync();

        return userClaims.Concat(roleClaims)
            .Select(claim => new Claim(claim.ClaimType, claim.ClaimValue))
            .ToArray();
    }

    private static AccountResult Validate(string claimType, string claimValue, string scope)
    {
        if (string.IsNullOrWhiteSpace(claimType) || claimType.Length > 128 ||
            !claimType.StartsWith("panda:", StringComparison.Ordinal) || Reserved.Contains(claimType))
            return AccountResult.Fail("InvalidClaimType", "Custom claims must use a non-reserved panda: namespace.");
        if (string.IsNullOrWhiteSpace(claimValue) || claimValue.Length > 2048)
            return AccountResult.Fail("InvalidClaimValue", "Claim value is required and must not exceed 2048 characters.");
        if (string.IsNullOrWhiteSpace(scope) || scope.Length > 128 || scope.Any(char.IsWhiteSpace))
            return AccountResult.Fail("InvalidClaimScope", "Claim scope is required and must not contain whitespace.");
        return AccountResult.Success;
    }
}
