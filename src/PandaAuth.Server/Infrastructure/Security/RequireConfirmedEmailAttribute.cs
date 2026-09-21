using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using System.Security.Claims;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>Admin mutations require a currently active, email-confirmed actor.</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class RequireConfirmedEmailAttribute : Attribute, IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var request = context.HttpContext.Request;
        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method) ||
            HttpMethods.IsOptions(request.Method)) return;

        var principal = context.HttpContext.User;
        var subject = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var db = context.HttpContext.RequestServices.GetRequiredService<PandaAuthDbContext>();
        if (subject is null || !await db.Users.AsNoTracking().AnyAsync(
                user => user.Id == subject && user.EmailConfirmed && user.Status == UserStatus.Active,
                context.HttpContext.RequestAborted))
            context.Result = new ForbidResult();
    }
}
