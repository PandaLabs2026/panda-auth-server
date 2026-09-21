using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed record AccountError(string Code, string Description);
public sealed record AccountResult(bool Succeeded, params AccountError[] Errors)
{
    public static AccountResult Success => new(true);
    public static AccountResult Fail(string code, string description) => new(false, new AccountError(code, description));
}

/// <summary>Account persistence and credentials. Every mutation uses an optimistic concurrency stamp.</summary>
public sealed class UserService(PandaAuthDbContext db, IPasswordHasher hasher, TimeProvider clock)
{
    public IQueryable<PandaUser> Users => db.Users;
    internal static string? Normalize(string? value) => value?.Normalize().ToUpperInvariant();
    public string? NormalizeEmail(string? email) => Normalize(email);
    public Task<PandaUser?> FindByIdAsync(string id) => db.Users.SingleOrDefaultAsync(x => x.Id == id);
    public Task<PandaUser?> FindByNameAsync(string name)
    {
        var normalized = Normalize(name);
        return db.Users.SingleOrDefaultAsync(x => x.NormalizedUserName == normalized);
    }
    public Task<PandaUser?> FindByEmailAsync(string email)
    {
        var normalized = Normalize(email);
        return db.Users.SingleOrDefaultAsync(x => x.NormalizedEmail == normalized);
    }
    public Task<PandaUser?> GetUserAsync(ClaimsPrincipal principal)
        => FindByIdAsync(principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue("sub") ?? "");

    public async Task<AccountResult> CreateAsync(PandaUser user, string? password = null)
    {
        var validation = await ValidateAsync(user);
        if (!validation.Succeeded) return validation;
        if (password is not null)
        {
            validation = ValidatePassword(password);
            if (!validation.Succeeded) return validation;
            user.PasswordHash = hasher.Hash(password);
        }
        db.Users.Add(user);
        return await SaveAsync();
    }

    public async Task<AccountResult> UpdateAsync(PandaUser user)
    {
        var validation = await ValidateAsync(user);
        if (!validation.Succeeded) return validation;
        db.Entry(user).Property(x => x.ConcurrencyStamp).OriginalValue = user.ConcurrencyStamp;
        user.ConcurrencyStamp = Guid.NewGuid().ToString();
        user.UpdatedAt = clock.GetUtcNow();
        db.Users.Update(user);
        return await SaveAsync();
    }

    private async Task<AccountResult> ValidateAsync(PandaUser user)
    {
        if (string.IsNullOrWhiteSpace(user.UserName) || user.UserName.Length > 256 ||
            user.UserName.Any(c => !"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+".Contains(c)))
            return AccountResult.Fail("InvalidUserName", "User name contains invalid characters.");
        if (user.Email?.Length > 256)
            return AccountResult.Fail("InvalidEmail", "Email is too long.");
        user.NormalizedUserName = Normalize(user.UserName);
        user.NormalizedEmail = Normalize(user.Email);
        if (await db.Users.AnyAsync(x => x.Id != user.Id && x.NormalizedUserName == user.NormalizedUserName))
            return AccountResult.Fail("DuplicateUserName", "User name is already taken.");
        if (user.NormalizedEmail is not null &&
            await db.Users.AnyAsync(x => x.Id != user.Id && x.NormalizedEmail == user.NormalizedEmail))
            return AccountResult.Fail("DuplicateEmail", "Email is already taken.");
        return AccountResult.Success;
    }

    internal static AccountResult ValidatePassword(string password)
        => password.Length >= 10 && password.Any(char.IsAsciiDigit) &&
           password.Any(char.IsAsciiLetterLower) && password.Any(char.IsAsciiLetterUpper) &&
           password.Any(c => !char.IsAsciiLetterOrDigit(c))
            ? AccountResult.Success
            : AccountResult.Fail("PasswordPolicy", "Passwords must be at least 10 characters and contain uppercase, lowercase, digit and non-alphanumeric characters.");

    public async Task<AccountResult> ReplacePasswordAsync(PandaUser user, string password)
    {
        var result = ValidatePassword(password);
        if (!result.Succeeded) return result;
        user.PasswordHash = hasher.Hash(password);
        user.SecurityStamp = Guid.NewGuid().ToString();
        return await UpdateAsync(user);
    }

    public Task<bool> CheckPasswordAsync(PandaUser user, string password)
        => Task.FromResult(hasher.Verify(user.PasswordHash, password) != PasswordVerificationOutcome.Failed);

    public Task<AccountResult> UpdateSecurityStampAsync(PandaUser user)
    {
        user.SecurityStamp = Guid.NewGuid().ToString();
        return UpdateAsync(user);
    }

    public Task<AccountResult> SetLockoutEndDateAsync(PandaUser user, DateTimeOffset? end)
    {
        user.LockoutEnd = end;
        return UpdateAsync(user);
    }

    public Task<AccountResult> ResetAccessFailedCountAsync(PandaUser user)
    {
        user.AccessFailedCount = 0;
        return UpdateAsync(user);
    }

    public async Task<IList<string>> GetRolesAsync(PandaUser user)
        => await (from membership in db.UserRoles
                  join role in db.Roles on membership.RoleId equals role.Id
                  where membership.UserId == user.Id
                  select role.Name!).ToListAsync();

    public Task<AccountResult> AddToRoleAsync(PandaUser user, string role)
        => AddToRolesAsync(user, [role]);

    public async Task<AccountResult> AddToRolesAsync(PandaUser user, IEnumerable<string> roles)
    {
        var names = roles.Select(Normalize).Distinct().ToArray();
        var found = await db.Roles.Where(x => names.Contains(x.NormalizedName)).ToListAsync();
        if (found.Count != names.Length) return AccountResult.Fail("RoleNotFound", "Role does not exist.");
        var current = await db.UserRoles.Where(x => x.UserId == user.Id).Select(x => x.RoleId).ToListAsync();
        db.UserRoles.AddRange(found.Where(x => !current.Contains(x.Id))
            .Select(x => new PandaUserRole { UserId = user.Id, RoleId = x.Id }));
        user.SecurityStamp = Guid.NewGuid().ToString();
        return await UpdateAsync(user);
    }

    public async Task<AccountResult> RemoveFromRoleAsync(PandaUser user, string role)
    {
        var normalized = Normalize(role);
        var ids = db.Roles.Where(x => x.NormalizedName == normalized).Select(x => x.Id);
        db.UserRoles.RemoveRange(await db.UserRoles.Where(x => x.UserId == user.Id && ids.Contains(x.RoleId)).ToListAsync());
        user.SecurityStamp = Guid.NewGuid().ToString();
        return await UpdateAsync(user);
    }

    internal async Task<AccountResult> SaveAsync()
    {
        try
        {
            await db.SaveChangesAsync();
            return AccountResult.Success;
        }
        catch (DbUpdateConcurrencyException)
        {
            db.ChangeTracker.Clear();
            return AccountResult.Fail("ConcurrencyFailure", "Account changed concurrently; retry the operation.");
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            db.ChangeTracker.Clear();
            return AccountResult.Fail("DuplicateAccount", "User name, email or role is already taken.");
        }
    }

    internal async Task<PandaUser?> ReloadAsync(string id)
    {
        db.ChangeTracker.Clear();
        return await FindByIdAsync(id);
    }

    internal async Task<LoginOutcome> VerifyLoginAsync(PandaUser user, string password, bool lockoutOnFailure)
    {
        // Re-verify after a conflict: a concurrent password/status update must never allow a stale login.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var verification = hasher.Verify(user.PasswordHash, password);
            if (user.Status != UserStatus.Active) return new(false, IsNotAllowed: true);
            if (user.LockoutEnabled && user.LockoutEnd > clock.GetUtcNow()) return new(false, IsLockedOut: true);
            var success = verification != PasswordVerificationOutcome.Failed;
            if (success && user.TwoFactorEnabled)
                return new(false, IsNotAllowed: true, User: user, RequiresMfaReconfiguration: true);
            if (success)
            {
                user.AccessFailedCount = 0;
                if (verification == PasswordVerificationOutcome.SuccessRehashNeeded)
                    user.PasswordHash = hasher.Hash(password);
            }
            else if (lockoutOnFailure && user.LockoutEnabled)
            {
                user.AccessFailedCount++;
                if (user.AccessFailedCount >= 5)
                {
                    user.LockoutEnd = clock.GetUtcNow().AddMinutes(5);
                    user.AccessFailedCount = 0;
                }
            }
            var result = await UpdateAsync(user);
            if (result.Succeeded)
                return new(
                    success,
                    IsLockedOut: !success && user.LockoutEnabled && user.LockoutEnd > clock.GetUtcNow(),
                    User: success ? user : null);
            if (!result.Errors.Any(x => x.Code == "ConcurrencyFailure")) return new(false);
            var reloaded = await ReloadAsync(user.Id);
            if (reloaded is null) return new(false);
            user = reloaded;
        }
        return new(false);
    }
}

public sealed class RoleService(PandaAuthDbContext db)
{
    public Task<PandaRole?> FindByNameAsync(string name)
    {
        var normalized = UserService.Normalize(name);
        return db.Roles.SingleOrDefaultAsync(x => x.NormalizedName == normalized);
    }
    public async Task<bool> RoleExistsAsync(string name) => await FindByNameAsync(name) is not null;
    public async Task<AccountResult> CreateAsync(PandaRole role)
    {
        if (string.IsNullOrWhiteSpace(role.Name) || role.Name.Length > 256)
            return AccountResult.Fail("InvalidRoleName", "Role name is required and must not exceed 256 characters.");
        if (await RoleExistsAsync(role.Name)) return AccountResult.Fail("DuplicateRoleName", "Role already exists.");
        role.NormalizedName = UserService.Normalize(role.Name);
        db.Roles.Add(role);
        try { await db.SaveChangesAsync(); return AccountResult.Success; }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            db.Entry(role).State = EntityState.Detached;
            return AccountResult.Fail("DuplicateRoleName", "Role already exists.");
        }
    }
}
