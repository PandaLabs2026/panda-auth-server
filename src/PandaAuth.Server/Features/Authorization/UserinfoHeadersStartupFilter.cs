namespace PandaAuth.Server.Features.Authorization;

/// <summary>Runs outside authentication so rejected bearer tokens cannot bypass cache policy.</summary>
internal sealed class UserinfoHeadersStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, pipeline) =>
        {
            if (context.Request.Path.Equals("/connect/userinfo", StringComparison.OrdinalIgnoreCase))
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers.CacheControl = "no-store";
                    context.Response.Headers.Vary = "Authorization";
                    return Task.CompletedTask;
                });
            await pipeline(context);
        });
        next(app);
    };
}
