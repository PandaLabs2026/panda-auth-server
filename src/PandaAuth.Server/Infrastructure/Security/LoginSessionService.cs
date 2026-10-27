using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using PandaAuth.Server.Features.SessionState;

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

public sealed class LoginSessionService(UserService users, TimeProvider clock, IConfiguration? configuration = null)
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
        // RecoveryCode 自 AUTH-DELIVERY-002 起可作为登录挑战的完成方式（Passkey 退役后的
        // 存量账号自救通道）：签入的 amr=recovery_code 只满足普通写操作窗，高风险操作
        // 仍需 TOTP 操作授权，不构成提权。
        if (method is not (MfaClaimTypes.Totp or MfaClaimTypes.RecoveryCode))
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
            new(PandaAuthClaims.SecurityVersion, AccountSecurityVersion.From(current)),
            new(AuthenticatedAtClaim, clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new(PandaAuthClaims.SsoSessionId, Guid.NewGuid().ToString("N")),
        };
        if (method is not null)
        {
            claims.Add(new Claim(MfaClaimTypes.Method, method));
            claims.Add(new Claim(MfaClaimTypes.VerifiedAt,
                clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }
        return new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme));
    }

    public async Task SignOutAsync(HttpContext context)
    {
        var ticket = await context.AuthenticateAsync(Scheme);
        if (configuration?.GetValue<bool>(PandaAuthSessionApi.SharedLogoutEnabled) == true &&
            ticket.Principal?.FindFirstValue(PandaAuthClaims.SsoSessionId) is { } sid)
            await context.RequestServices.GetRequiredService<SessionRevocationService>()
                .RevokeAsync(PandaAuthSessionApi.SsoPartition, sid, context.RequestAborted);
        await context.SignOutAsync(Scheme);
    }

    public async Task SignInForMfaReconfigurationAsync(HttpContext context, PandaUser user)
    {
        var current = await users.ReloadAsync(user.Id);
        if (current is null || current.Status != UserStatus.Active || !current.TwoFactorEnabled)
            throw new InvalidOperationException("MFA reconfiguration is not required.");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, current.Id),
            new Claim(StampClaim, current.SecurityStamp ?? ""),
            new Claim(PandaAuthClaims.SecurityVersion, AccountSecurityVersion.From(current)),
            new Claim(PandaAuthClaims.SsoSessionId, Guid.NewGuid().ToString("N")),
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
               user.SecurityStamp == ticket.Principal.FindFirstValue(StampClaim) && AccountSecurityVersion.Matches(ticket.Principal, user)
            ? user
            : null;
    }

    public Task SignOutReconfigurationAsync(HttpContext context) => context.SignOutAsync(ReconfigurationScheme);

    /// <summary>Rotates the current IDP cookie after a verified MFA ceremony without altering its subject or lifetime.</summary>
    public async Task MarkMfaAsync(HttpContext context, string method)
    {
        if (method is not (MfaClaimTypes.Totp or MfaClaimTypes.RecoveryCode))
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

    /// <summary>Each validation reads authoritative account state; a pending old read cannot restore acceptance.</summary>
    internal static async Task ValidateCookieAsync(
        CookieValidatePrincipalContext context, UserService users,
        SessionRevocationService? revocations = null)
    {
        var principal = context.Principal!;
        var ids = principal.FindAll(PandaAuthClaims.SsoSessionId).ToArray();
        if (ids.Length != 1 || !Guid.TryParseExact(ids[0].Value, "N", out _))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);
            return;
        }
        if (revocations is not null && await revocations.IsRevokedAsync(PandaAuthSessionApi.SsoPartition,
            principal.FindFirstValue(PandaAuthClaims.SsoSessionId)!, context.HttpContext.RequestAborted))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);
            return;
        }
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue("sub");
        var stamp = principal.FindFirstValue(StampClaim);
        var user = await users.FindByIdAsync(userId ?? string.Empty);
        if (user is null || user.Status != UserStatus.Active || string.IsNullOrEmpty(user.SecurityStamp) ||
            user.SecurityStamp != stamp || !AccountSecurityVersion.Matches(principal, user))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);
            return;
        }

    }
}

public static class UserStoreRegistration
{
    /// <param name="cookieSecure">会话 cookie 的 Secure 属性策略（Auth:CookieSecure）。</param>
    public static IServiceCollection AddUserStore(
        this IServiceCollection services,
        PandaAuth.Server.Configuration.CookieSecurePolicy cookieSecure = PandaAuth.Server.Configuration.CookieSecurePolicy.SameAsRequest)
    {
        // CookieSecure 与 HttpsRequired（OpenIddict transport requirement）解耦：网关终止 TLS 后
        // 回源为 http 的部署（fleet 控制面等，HttpsRequired=false）下，Secure 若跟随回源协议
        // （SameAsRequest）会被网关链路剥离（auth.appliket.com 实测），需单独收紧为 Always。
        var securePolicy = cookieSecure == PandaAuth.Server.Configuration.CookieSecurePolicy.Always
            ? CookieSecurePolicy.Always
            : CookieSecurePolicy.SameAsRequest;
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IPasswordHasher, Argon2idPasswordHasher>();
        services.TryAddScoped<SessionRevocationService>();
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
                options.Cookie.SecurePolicy = securePolicy;
                // Resolve scoped authoritative stores for each validation.
                options.Events.OnValidatePrincipal = async context =>
                {
                    await LoginSessionService.ValidateCookieAsync(
                        context,
                        context.HttpContext.RequestServices.GetRequiredService<UserService>(),
                        context.HttpContext.RequestServices.GetRequiredService<SessionRevocationService>());
                };
            })
            .AddCookie(LoginSessionService.ReconfigurationScheme, options =>
            {
                options.Cookie.Name = LoginSessionService.ReconfigurationScheme;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = securePolicy;
                options.Events.OnValidatePrincipal = async context =>
                {
                    await LoginSessionService.ValidateCookieAsync(
                        context,
                        context.HttpContext.RequestServices.GetRequiredService<UserService>(),
                        context.HttpContext.RequestServices.GetRequiredService<SessionRevocationService>());
                };
            });
        return services;
    }
}
