using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

public sealed class ProfileOptions
{
    public bool Enabled { get; set; }
    public bool MeClientEnabled { get; set; }
    public string[] AllowedClients { get; set; } = [];
}

internal static class ProfileAccess
{
    public const string ReadPolicy = "self-profile-read";
    public const string WritePolicy = "self-profile-write";
    public static bool IsPath(PathString path) => path.StartsWithSegments(PandaAuthProfileApi.Self, StringComparison.OrdinalIgnoreCase);
    public static string? ActorId(ClaimsPrincipal principal)
    {
        var subjects = principal.GetClaims(OpenIddictConstants.Claims.Subject);
        return subjects is { Length: 1 } && subjects[0].Length is > 0 and <= 450 ? subjects[0] : null;
    }
    public static bool HasResource(ClaimsPrincipal principal, string scope, ProfileOptions options)
        => principal.Identity?.IsAuthenticated == true
           && principal.GetClaim(PandaAuthClaims.SubjectType) == PandaAuthClaims.SubjectTypes.Human
           && principal.HasAudience(ProfileScopes.Resource) && principal.HasScope(scope)
           && principal.GetPresenters() is { Length: 1 } presenters
           && options.AllowedClients.Contains(presenters[0], StringComparer.Ordinal);
}

internal sealed record ProfileResourceRequirement(string Scope) : IAuthorizationRequirement;

internal sealed class ProfileResourceHandler(PandaAuthDbContext db, IOptions<ProfileOptions> options)
    : AuthorizationHandler<ProfileResourceRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, ProfileResourceRequirement requirement)
    {
        var id = ProfileAccess.ActorId(context.User);
        if (id is null)
        {
            context.Fail(new AuthorizationFailureReason(this, "profile_identity_invalid"));
            return;
        }
        if (!options.Value.Enabled || !ProfileAccess.HasResource(context.User, requirement.Scope, options.Value)) return;
        var ct = (context.Resource as HttpContext)?.RequestAborted ?? CancellationToken.None;
        if (await db.Users.AsNoTracking().AnyAsync(u => u.Id == id && u.Status == UserStatus.Active, ct))
            context.Succeed(requirement);
    }
}

/// <summary>Keep standard authorization behavior elsewhere; profile rejections use its private error contract.</summary>
internal sealed class ProfileAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler standard = new();
    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult result)
    {
        if (!ProfileAccess.IsPath(context.Request.Path) || result.Succeeded)
        {
            await standard.HandleAsync(next, context, policy, result);
            return;
        }
        var invalidIdentity = result.AuthorizationFailure?.FailureReasons.Any(r => r.Message == "profile_identity_invalid") == true;
        var status = result.Challenged || invalidIdentity ? 401 : 403;
        var code = status == 401 ? "profile_identity_invalid" : "profile_permission_denied";
        context.Response.StatusCode = status;
        if (status == 401) context.Response.Headers.WWWAuthenticate = "Bearer";
        var actor = context.User.GetClaim(PandaAuthClaims.SubjectType) == PandaAuthClaims.SubjectTypes.Human
            ? ProfileAccess.ActorId(context.User) : null;
        await context.RequestServices.GetRequiredService<SecurityEventWriter>().RecordAsync(
            new SecurityEventEntry("profile.access.denied", actor, actor, "profile", null, null,
                new { outcome = code }, null, null, context.TraceIdentifier), context.RequestAborted);
        await context.Response.WriteAsJsonAsync(new ProfileErrorDto(code, context.TraceIdentifier), context.RequestAborted);
    }
}

internal static class ProfileRegistration
{
    public static IServiceCollection AddSelfProfiles(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<ProfileOptions>(configuration.GetSection("Profile"));
        services.AddScoped<SelfProfileService>();
        services.AddScoped<ProfileContactService>();
        services.AddSingleton<ProfileAvatarDecoder>();
        services.AddScoped<ProfileAvatarService>();
        services.AddHostedService<ProfileContactRetention>();
        services.AddScoped<IAuthorizationHandler, ProfileResourceHandler>();
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, ProfileAuthorizationResultHandler>();
        services.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter, ProfileHeadersStartupFilter>();
        services.AddAuthorization(options =>
        {
            Add(ProfileAccess.ReadPolicy, ProfileScopes.Read);
            Add(ProfileAccess.WritePolicy, ProfileScopes.Write);
            void Add(string name, string scope) => options.AddPolicy(name, policy => policy
                .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser().AddRequirements(new ProfileResourceRequirement(scope)));
        });
        return services;
    }
}
