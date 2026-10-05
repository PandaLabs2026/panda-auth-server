using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
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

/// <summary>
/// Account persistence and credentials. Every mutation uses an optimistic concurrency stamp.
/// 只读查找（ById/ByName）走 AsNoTracking：cookie 校验等热路径每请求一查，无变更跟踪负担；
/// 所有变更路径都经 <see cref="UpdateAsync"/>（对游离实体显式 Attach+Modified），不受影响。
/// 非 sealed 且查找方法 virtual：stamp 缓存行为测试以可数桩子类观测查库次数。
/// </summary>
public class UserService(
    PandaAuthDbContext db, IPasswordHasher hasher, TimeProvider clock, IMemoryCache? stampCache = null)
{
    public IQueryable<PandaUser> Users => db.Users;
    internal static string? Normalize(string? value) => value?.Normalize().ToUpperInvariant();
    public string? NormalizeEmail(string? email) => Normalize(email);
    public virtual Task<PandaUser?> FindByIdAsync(string id)
        => db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id);
    public virtual Task<PandaUser?> FindByNameAsync(string name)
    {
        var normalized = Normalize(name);
        return db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.NormalizedUserName == normalized);
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
        // 只读查找已改 AsNoTracking：同一作用域内「已附着旧实例 → 再更新新取的游离实例」会撞键
        // （IdentityMap 冲突）。不可用 Detach 让旧实例出局——Detach 会级联分离其依赖实体，
        // 把 AddRange 尚未保存的角色成员等 pending 变更一并丢弃（实测）。改为把调用方实例的
        // 当前值转移到已跟踪实例上，后续更新以跟踪实例执行。
        var caller = user;
        var tracked = db.Users.Local.FirstOrDefault(existing => existing.Id == user.Id);
        if (tracked is not null && !ReferenceEquals(tracked, user))
        {
            db.Entry(tracked).CurrentValues.SetValues(user);
            user = tracked;
        }
        db.Entry(user).Property(x => x.ConcurrencyStamp).OriginalValue = user.ConcurrencyStamp;
        user.ConcurrencyStamp = Guid.NewGuid().ToString();
        user.UpdatedAt = clock.GetUtcNow();
        db.Users.Update(user);
        var result = await SaveAsync();
        // 值转移到跟踪实例后，调用方实例仍是旧令牌：同请求内对同一游离实例连续两次 UpdateAsync
        // 的既有流（如 Unlock 的清锁+清计数）会把旧令牌当 OriginalValue 重放而并发失败——
        // 成功后把新令牌回写调用方实例，保持与旧 tracked 别名等价的语义。
        if (result.Succeeded && !ReferenceEquals(user, caller))
        {
            caller.ConcurrencyStamp = user.ConcurrencyStamp;
            caller.UpdatedAt = user.UpdatedAt;
        }
        return result;
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
        var previousStamp = user.SecurityStamp;
        user.PasswordHash = hasher.Hash(password);
        user.SecurityStamp = Guid.NewGuid().ToString();
        var update = await UpdateAsync(user);
        // 改密的契约是「旧会话立即作废」（LoginCookieTests 钉住）：stamp 短缓存里的旧键必须同步失效，
        // 否则被偷的 cookie 在 TTL 内多活 60 秒。
        if (update.Succeeded) InvalidateStampCache(user.Id, previousStamp);
        return update;
    }

    public Task<bool> CheckPasswordAsync(PandaUser user, string password)
        => Task.FromResult(hasher.Verify(user.PasswordHash, password) != PasswordVerificationOutcome.Failed);

    public async Task<AccountResult> UpdateSecurityStampAsync(PandaUser user)
    {
        var previousStamp = user.SecurityStamp;
        user.SecurityStamp = Guid.NewGuid().ToString();
        var update = await UpdateAsync(user);
        // stamp 轮换即踢会话：同步作废旧 stamp 的缓存键（见 ReplacePasswordAsync 注释）。
        if (update.Succeeded) InvalidateStampCache(user.Id, previousStamp);
        return update;
    }

    /// <summary>stamp 轮换路径共用：旧 stamp 的 cookie 校验缓存键即时失效（无缓存宿主为 no-op）。</summary>
    private void InvalidateStampCache(string userId, string? previousStamp)
    {
        if (stampCache is null || string.IsNullOrEmpty(previousStamp)) return;
        stampCache.Remove(LoginSessionService.StampCacheKeyPrefix + userId + ":" + previousStamp);
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
        var previousStamp = user.SecurityStamp;
        user.SecurityStamp = Guid.NewGuid().ToString();
        var update = await UpdateAsync(user);
        if (update.Succeeded) InvalidateStampCache(user.Id, previousStamp);
        return update;
    }

    public async Task<AccountResult> RemoveFromRoleAsync(PandaUser user, string role)
    {
        var normalized = Normalize(role);
        var ids = db.Roles.Where(x => x.NormalizedName == normalized).Select(x => x.Id);
        db.UserRoles.RemoveRange(await db.UserRoles.Where(x => x.UserId == user.Id && ids.Contains(x.RoleId)).ToListAsync());
        var previousStamp = user.SecurityStamp;
        user.SecurityStamp = Guid.NewGuid().ToString();
        var update = await UpdateAsync(user);
        if (update.Succeeded) InvalidateStampCache(user.Id, previousStamp);
        return update;
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
