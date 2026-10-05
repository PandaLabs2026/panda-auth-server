using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// The verified account is returned only for a successful sign-in. Callers that mutate the
/// account afterwards must use it instead of the potentially stale instance they supplied.
/// </summary>
public sealed record LoginOutcome(
    bool Succeeded,
    bool IsLockedOut = false,
    bool IsNotAllowed = false,
    PandaUser? User = null,
    bool RequiresMfaReconfiguration = false);

public sealed class LoginSessionService(UserService users, TimeProvider clock)
{
    public const string Scheme = "PandaAuth.Login.v2";
    public const string ReconfigurationScheme = "PandaAuth.MfaReconfiguration.v1";
    public const string StampClaim = "panda_security_stamp";
    public const string AuthenticatedAtClaim = "panda_authenticated_at";

    public Task<LoginOutcome> CheckPasswordSignInAsync(PandaUser user, string password, bool lockoutOnFailure)
        => users.VerifyLoginAsync(user, password, lockoutOnFailure);

    public async Task SignInAsync(HttpContext context, PandaUser user, bool isPersistent)
    {
        var principal = await BuildPrincipalAsync(user, method: null);
        await context.SignInAsync(Scheme, principal, new AuthenticationProperties { IsPersistent = isPersistent });
    }

    /// <summary>
    /// 登录路径 MFA 挑战成功后的签入：会话自诞生起携带 MFA 事实（Method/VerifiedAt），
    /// 不经过「先签入再 MarkMfaAsync 轮换」的两步窗口。
    /// </summary>
    public async Task SignInWithMfaAsync(HttpContext context, PandaUser user, string method)
    {
        if (method is not (MfaClaimTypes.WebAuthn or MfaClaimTypes.Totp))
        {
            throw new ArgumentOutOfRangeException(nameof(method));
        }
        var principal = await BuildPrincipalAsync(user, method);
        await context.SignInAsync(Scheme, principal, new AuthenticationProperties { IsPersistent = false });
    }

    private async Task<ClaimsPrincipal> BuildPrincipalAsync(PandaUser user, string? method)
    {
        // Fetch again after optimistic retries; never issue a ticket from stale account state.
        var current = await users.ReloadAsync(user.Id);
        if (current is null || current.Status != UserStatus.Active ||
            current.SecurityStamp != user.SecurityStamp)
            throw new InvalidOperationException("Account changed during sign-in.");
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, current.Id),
            new(ClaimTypes.Name, current.UserName ?? current.Id),
            new(StampClaim, current.SecurityStamp ?? ""),
            new(AuthenticatedAtClaim, clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };
        if (method is not null)
        {
            claims.Add(new Claim(MfaClaimTypes.Method, method));
            claims.Add(new Claim(MfaClaimTypes.VerifiedAt,
                clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }
        return new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme));
    }

    public Task SignOutAsync(HttpContext context) => context.SignOutAsync(Scheme);

    public async Task SignInForMfaReconfigurationAsync(HttpContext context, PandaUser user)
    {
        var current = await users.ReloadAsync(user.Id);
        if (current is null || current.Status != UserStatus.Active || !current.TwoFactorEnabled)
            throw new InvalidOperationException("MFA reconfiguration is not required.");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, current.Id),
            new Claim(StampClaim, current.SecurityStamp ?? ""),
        ], ReconfigurationScheme));
        await context.SignInAsync(ReconfigurationScheme, principal,
            new AuthenticationProperties { IsPersistent = false, AllowRefresh = false });
    }

    public async Task<PandaUser?> GetReconfigurationUserAsync(HttpContext context)
    {
        var ticket = await context.AuthenticateAsync(ReconfigurationScheme);
        if (!ticket.Succeeded || ticket.Principal is null) return null;
        var user = await users.GetUserAsync(ticket.Principal);
        return user is not null && user.Status == UserStatus.Active && user.TwoFactorEnabled &&
               user.SecurityStamp == ticket.Principal.FindFirstValue(StampClaim)
            ? user
            : null;
    }

    public Task SignOutReconfigurationAsync(HttpContext context) => context.SignOutAsync(ReconfigurationScheme);

    /// <summary>Rotates the current IDP cookie after a verified MFA ceremony without altering its subject or lifetime.</summary>
    public async Task MarkMfaAsync(HttpContext context, string method)
    {
        if (method is not (MfaClaimTypes.WebAuthn or MfaClaimTypes.Totp or MfaClaimTypes.RecoveryCode))
        {
            throw new ArgumentOutOfRangeException(nameof(method));
        }

        var ticket = await context.AuthenticateAsync(Scheme);
        if (!ticket.Succeeded || ticket.Principal is null)
        {
            throw new InvalidOperationException("当前登录会话无效。");
        }

        var identity = new ClaimsIdentity(ticket.Principal.Claims.Where(claim =>
            claim.Type is not MfaClaimTypes.Method and not MfaClaimTypes.VerifiedAt), Scheme);
        identity.AddClaim(new Claim(MfaClaimTypes.Method, method));
        identity.AddClaim(new Claim(MfaClaimTypes.VerifiedAt,
            clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
        await context.SignInAsync(Scheme, new ClaimsPrincipal(identity), ticket.Properties);
    }

    /// <summary>stamp 短缓存键前缀；键含 userId+stamp——stamp 轮换（改密/改角色）即 miss、立即生效。</summary>
    internal const string StampCacheKeyPrefix = "login-stamp-valid:";

    /// <summary>stamp 缓存 TTL：用户状态变化（冻结等不轮换 stamp 的路径）最迟 60 秒生效的取舍窗口。</summary>
    internal static readonly TimeSpan StampCacheTtl = TimeSpan.FromSeconds(60);

    /// <summary>
    /// 每个 cookie 认证请求都会走到这里：命中 stamp 短缓存即免查库（热路径大头）。
    /// 取舍：改密/改角色等轮换 stamp 的操作会同步作废旧 stamp 的缓存键（UserService 轮换路径负责），
    /// 旧会话立即失效；冻结等不轮换 stamp 的状态变化最迟 60 秒（TTL）后生效。
    /// 校验失败绝不写缓存（fail-closed 不缓存否定结果）。
    /// 经 AddUserStore 的事件委托逐请求解析 UserService/IMemoryCache；internal static 供缓存行为直测。
    /// </summary>
    internal static async Task ValidateCookieAsync(
        CookieValidatePrincipalContext context, UserService users, IMemoryCache stampCache)
    {
        var principal = context.Principal!;
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue("sub");
        var stamp = principal.FindFirstValue(StampClaim);
        if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(stamp) &&
            stampCache.TryGetValue(StampCacheKeyPrefix + userId + ":" + stamp, out _))
        {
            return;
        }

        var user = await users.FindByIdAsync(userId ?? string.Empty);
        if (user is null || user.Status != UserStatus.Active || string.IsNullOrEmpty(user.SecurityStamp) ||
            user.SecurityStamp != stamp)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(Scheme);
            return;
        }

        stampCache.Set(StampCacheKeyPrefix + user.Id + ":" + user.SecurityStamp, true, StampCacheTtl);
    }
}

public static class UserStoreRegistration
{
    public static IServiceCollection AddUserStore(this IServiceCollection services, bool httpsRequired = false)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IPasswordHasher, Argon2idPasswordHasher>();
        services.AddScoped<UserService>();
        services.AddScoped<RoleService>();
        services.AddScoped<LoginSessionService>();
        services.AddAuthentication(LoginSessionService.Scheme)
            .AddCookie(LoginSessionService.Scheme, options =>
            {
                options.LoginPath = "/account/login";
                options.Cookie.Name = LoginSessionService.Scheme;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = httpsRequired ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
                // 静态事件改为委托：逐请求从 RequestServices 解析 UserService 与 stamp 缓存
                // （ValidateCookieAsync 需要作用域服务与 IMemoryCache，静态签名拿不到）。
                options.Events.OnValidatePrincipal = async context =>
                {
                    await LoginSessionService.ValidateCookieAsync(
                        context,
                        context.HttpContext.RequestServices.GetRequiredService<UserService>(),
                        context.HttpContext.RequestServices.GetRequiredService<IMemoryCache>());
                };
            })
            .AddCookie(LoginSessionService.ReconfigurationScheme, options =>
            {
                options.Cookie.Name = LoginSessionService.ReconfigurationScheme;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = httpsRequired ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
                options.Events.OnValidatePrincipal = async context =>
                {
                    await LoginSessionService.ValidateCookieAsync(
                        context,
                        context.HttpContext.RequestServices.GetRequiredService<UserService>(),
                        context.HttpContext.RequestServices.GetRequiredService<IMemoryCache>());
                };
            });
        return services;
    }
}
