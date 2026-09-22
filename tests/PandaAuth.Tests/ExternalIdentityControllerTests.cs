using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ExternalIdentityControllerTests
{
    [Fact]
    public async Task List_ReturnsOnlyActiveLinksForCurrentUser()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var first = new PandaUser { UserName = "external-list-first" };
        var second = new PandaUser { UserName = "external-list-second" };
        Assert.True((await users.CreateAsync(first, "Strong!Pass123")).Succeeded);
        Assert.True((await users.CreateAsync(second, "Strong!Pass123")).Succeeded);
        var links = provider.GetRequiredService<ExternalIdentityService>();
        await links.BindAsync(first.Id, "wechat", "subject-1", "Panda", null);
        await links.BindAsync(second.Id, "enterprise-wechat", "subject-2", "Other", null);
        var controller = CreateController(provider, first);

        var result = await controller.List(CancellationToken.None);

        var response = Assert.IsType<OkObjectResult>(result);
        var items = Assert.IsAssignableFrom<IReadOnlyList<ExternalIdentitySummary>>(response.Value);
        var item = Assert.Single(items);
        Assert.Equal("wechat", item.Provider);
        Assert.Equal("Panda", item.DisplayName);
    }

    [Fact]
    public async Task Unlink_RequiresRecentAuthentication()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "external-unlink-auth" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var link = await provider.GetRequiredService<ExternalIdentityService>()
            .BindAsync(user.Id, "wechat", "subject-auth", null, null);
        var controller = CreateController(provider, user);

        var result = await controller.Unlink(link.Identity!.Id, CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Unlink_WithRecentAuthentication_RemovesLink()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "external-unlink" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var link = await provider.GetRequiredService<ExternalIdentityService>()
            .BindAsync(user.Id, "wechat", "subject-unlink", null, null);
        var oldStamp = user.SecurityStamp;
        var controller = CreateController(provider, user, recentAuthentication: true);

        var result = await controller.Unlink(link.Identity!.Id, CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        Assert.Null(await provider.GetRequiredService<ExternalIdentityService>()
            .FindActiveAsync("wechat", "subject-unlink"));
        Assert.NotEqual(oldStamp, (await provider.GetRequiredService<UserService>().FindByIdAsync(user.Id))!.SecurityStamp);
    }

    private static ExternalIdentityController CreateController(
        ServiceProvider provider, PandaUser user, bool recentAuthentication = false)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(LoginSessionService.StampClaim, user.SecurityStamp!),
        };
        if (recentAuthentication)
        {
            claims.Add(new Claim(LoginSessionService.AuthenticatedAtClaim,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        }
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, LoginSessionService.Scheme));
        return new ExternalIdentityController(
            provider.GetRequiredService<ExternalIdentityService>(),
            provider.GetRequiredService<SessionSecurityService>())
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
    }
}
