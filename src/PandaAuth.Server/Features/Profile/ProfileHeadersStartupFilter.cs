using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Options;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

/// <summary>Outer pipeline placement covers bearer rejection and exceptions as well as controller responses.</summary>
internal sealed class ProfileHeadersStartupFilter(IOptions<ProfileOptions> options, Oasis.OasisProfileOptions oasis) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, pipeline) =>
        {
            if (ProfileAccess.IsPath(context.Request.Path))
            {
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers.CacheControl = "no-store";
                    return Task.CompletedTask;
                });
                if (!options.Value.Enabled || (ProfileAccess.IsOrganizationPath(context.Request.Path)
                    && (!options.Value.OrganizationsEnabled || !oasis.Enabled)))
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsJsonAsync(new ProfileErrorDto("profile_unavailable", context.TraceIdentifier), context.RequestAborted);
                    return;
                }
            }
            await pipeline(context);
        });
        next(app);
    };
}

internal sealed class ProfileRoutesDisabledConvention : IApplicationModelConvention
{
    public void Apply(ApplicationModel application)
    {
        for (var index = application.Controllers.Count - 1; index >= 0; index--)
            if (application.Controllers[index].ControllerType == typeof(SelfProfileController))
                application.Controllers.RemoveAt(index);
    }
}
