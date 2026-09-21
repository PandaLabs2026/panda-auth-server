using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public class AccountVerificationAuthorizationTests
{
    [Theory]
    [InlineData(typeof(AdminUsersController), false)]
    [InlineData(typeof(AdminUsersController), true)]
    [InlineData(typeof(AdminClientsController), false)]
    [InlineData(typeof(AdminClientsController), true)]
    public async Task AdminWrites_RequireCurrentConfirmedEmail(Type controller, bool confirmed)
    {
        var (provider, _) = AdminTestHost.Create();
        using (provider)
        {
            var db = provider.GetRequiredService<PandaAuthDbContext>();
            db.Users.Add(new PandaUser { Id = "actor-1", EmailConfirmed = confirmed });
            await db.SaveChangesAsync();
            var http = AdminTestHost.HttpContext(provider);
            http.Request.Method = "POST";
            var context = new AuthorizationFilterContext(new ActionContext(http, new RouteData(),
                new ControllerActionDescriptor { ControllerTypeInfo = controller.GetTypeInfo() }), []);
            var filter = Assert.Single(controller.GetCustomAttributes().OfType<IAsyncAuthorizationFilter>());
            await filter.OnAuthorizationAsync(context);
            if (confirmed) Assert.Null(context.Result);
            else Assert.IsType<ForbidResult>(context.Result);
        }
    }
}
