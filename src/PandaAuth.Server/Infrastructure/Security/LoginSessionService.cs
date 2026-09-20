using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PandaAuth.Server.Domain;
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
    PandaUser? User = null);

public sealed class LoginSessionService(UserService users)
{
    public const string Scheme = "PandaAuth.Login.v2";
    public const string StampClaim = "panda_security_stamp";

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
        ], Scheme));
        await context.SignInAsync(Scheme, principal, new AuthenticationProperties { IsPersistent = isPersistent });
    }

    public Task SignOutAsync(HttpContext context) => context.SignOutAsync(Scheme);

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
            });
        return services;
    }
}
