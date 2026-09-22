using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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
        // Fetch again after optimistic retries; never issue a ticket from stale account state.
        var current = await users.ReloadAsync(user.Id);
        if (current is null || current.Status != UserStatus.Active ||
            current.SecurityStamp != user.SecurityStamp)
            throw new InvalidOperationException("Account changed during sign-in.");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, current.Id),
            new Claim(ClaimTypes.Name, current.UserName ?? current.Id),
            new Claim(StampClaim, current.SecurityStamp ?? ""),
            new Claim(AuthenticatedAtClaim, clock.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
        ], Scheme));
        await context.SignInAsync(Scheme, principal, new AuthenticationProperties { IsPersistent = isPersistent });
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

    public static async Task ValidateCookieAsync(CookieValidatePrincipalContext context)
    {
        var users = context.HttpContext.RequestServices.GetRequiredService<UserService>();
        var user = await users.GetUserAsync(context.Principal!);
        if (user is null || user.Status != UserStatus.Active || string.IsNullOrEmpty(user.SecurityStamp) ||
            user.SecurityStamp != context.Principal!.FindFirstValue(StampClaim))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(Scheme);
        }
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
                options.Events.OnValidatePrincipal = LoginSessionService.ValidateCookieAsync;
            })
            .AddCookie(LoginSessionService.ReconfigurationScheme, options =>
            {
                options.Cookie.Name = LoginSessionService.ReconfigurationScheme;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = httpsRequired ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
                options.Events.OnValidatePrincipal = LoginSessionService.ValidateCookieAsync;
            });
        return services;
    }
}
