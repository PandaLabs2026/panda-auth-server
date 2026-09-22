using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ExternalIdentityServiceTests
{
    [Fact]
    public async Task BindAsync_CreatesProviderNeutralLinkWithoutEmailMerging()
    {
        using var provider = CreateProvider();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "external-user", Email = "local@example.com" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = provider.GetRequiredService<ExternalIdentityService>();

        var result = await service.BindAsync(user.Id, "wechat", "subject-1", "昵称", "local@example.com");

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Identity);
        Assert.Equal(user.Id, result.Identity!.UserId);
        Assert.Equal("wechat", result.Identity.Provider);
        Assert.Equal("subject-1", result.Identity.ProviderSubject);
        Assert.Equal("local@example.com", (await users.FindByEmailAsync("local@example.com"))!.Id == user.Id
            ? "local@example.com" : null);
        var securityEvent = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents
            .Where(item => item.EventType == "user.external_identity_linked"));
        Assert.Equal("user.external_identity_linked", securityEvent.EventType);
        Assert.Equal(user.Id, securityEvent.UserId);
    }

    [Fact]
    public async Task BindAsync_RejectsActiveProviderSubjectAlreadyLinkedToAnotherUser()
    {
        using var provider = CreateProvider();
        var users = provider.GetRequiredService<UserService>();
        var first = new PandaUser { UserName = "first" };
        var second = new PandaUser { UserName = "second" };
        Assert.True((await users.CreateAsync(first, "Strong!Pass123")).Succeeded);
        Assert.True((await users.CreateAsync(second, "Strong!Pass123")).Succeeded);
        var service = provider.GetRequiredService<ExternalIdentityService>();
        Assert.True((await service.BindAsync(first.Id, "wechat", "subject-1", null, null)).Succeeded);

        var result = await service.BindAsync(second.Id, "wechat", "subject-1", null, null);

        Assert.False(result.Succeeded);
        Assert.Equal("ExternalIdentityAlreadyLinked", result.ErrorCode);
    }

    [Fact]
    public async Task UnbindAsync_RejectsRemovingLastAvailableLoginMethod()
    {
        using var provider = CreateProvider();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "passwordless" };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        var service = provider.GetRequiredService<ExternalIdentityService>();
        var linked = await service.BindAsync(user.Id, "wechat", "subject-1", null, null);

        var result = await service.UnbindAsync(user.Id, linked.Identity!.Id);

        Assert.False(result.Succeeded);
        Assert.Equal("LastLoginMethod", result.ErrorCode);
    }

    [Fact]
    public async Task UnbindAsync_SucceedsWhenPasswordRemainsAndMarksLinkInactive()
    {
        using var provider = CreateProvider();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "password-user" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = provider.GetRequiredService<ExternalIdentityService>();
        var linked = await service.BindAsync(user.Id, "wechat", "subject-1", null, null);

        var result = await service.UnbindAsync(user.Id, linked.Identity!.Id);

        Assert.True(result.Succeeded);
        Assert.Null(await service.FindActiveAsync("wechat", "subject-1"));
        Assert.NotNull(await provider.GetRequiredService<PandaAuthDbContext>().ExternalIdentities
            .SingleAsync(identity => identity.Id == linked.Identity.Id && identity.UnlinkedAt != null));
        var securityEvent = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents
            .Where(item => item.EventType == "user.external_identity_unlinked"));
        Assert.Equal("user.external_identity_unlinked", securityEvent.EventType);
        Assert.Equal(user.Id, securityEvent.UserId);
    }

    [Fact]
    public async Task MarkUsedAsync_UpdatesOnlyTheActiveProviderSubject()
    {
        using var provider = CreateProvider();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "external-used" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = provider.GetRequiredService<ExternalIdentityService>();
        var linked = await service.BindAsync(user.Id, "WeChat", "subject-used", null, null);

        var marked = await service.MarkUsedAsync("wechat", "subject-used");

        Assert.NotNull(marked);
        Assert.Equal(linked.Identity!.Id, marked!.Id);
        Assert.NotNull(marked.LastUsedAt);
        Assert.Equal(marked.UpdatedAt, marked.LastUsedAt);
    }

    [Fact]
    public async Task BindVerifiedAsync_RequiresCurrentSessionRecentAuthenticationAndConfirmedEmail()
    {
        using var provider = CreateProvider();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "external-secure-bind", Email = "bind@example.com" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = provider.GetRequiredService<ExternalIdentityService>();
        var profile = new ExternalIdentityProfile("wechat", "subject-secure", "Panda", "bind@example.com");

        var noRecentAuth = await service.BindVerifiedAsync(user.Id, Principal(user), profile);
        Assert.False(noRecentAuth.Succeeded);
        Assert.Equal("RecentAuthenticationRequired", noRecentAuth.ErrorCode);

        user.EmailConfirmed = true;
        await provider.GetRequiredService<PandaAuthDbContext>().SaveChangesAsync();
        var recent = Principal(user, recent: true);
        var success = await service.BindVerifiedAsync(user.Id, recent, profile);

        Assert.True(success.Succeeded);
        Assert.Equal(user.Id, success.Identity!.UserId);
    }

    [Fact]
    public async Task BindVerifiedAsync_RejectsUnconfirmedEmailEvenWithRecentAuthentication()
    {
        using var provider = CreateProvider();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "external-unconfirmed", Email = "unconfirmed@example.com" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = provider.GetRequiredService<ExternalIdentityService>();

        var result = await service.BindVerifiedAsync(
            user.Id,
            Principal(user, recent: true),
            new ExternalIdentityProfile("wechat", "subject-unconfirmed", null, null));

        Assert.False(result.Succeeded);
        Assert.Equal("EmailConfirmationRequired", result.ErrorCode);
    }

    private static ClaimsPrincipal Principal(PandaUser user, bool recent = false)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(LoginSessionService.StampClaim, user.SecurityStamp!),
        };
        if (recent)
        {
            claims.Add(new Claim(LoginSessionService.AuthenticatedAtClaim,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        }
        return new ClaimsPrincipal(new ClaimsIdentity(claims, LoginSessionService.Scheme));
    }

    private static ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PandaAuthDbContext>(options => options.UseInMemoryDatabase(Guid.NewGuid().ToString("N")));
        services.AddSingleton(TimeProvider.System);
        services.AddUserStore();
        services.AddScoped<SecurityEventWriter>();
        services.AddSingleton<ITokenRevoker, NoopTokenRevoker>();
        services.AddScoped<SessionSecurityService>();
        services.AddScoped<ExternalIdentityService>();
        return services.BuildServiceProvider();
    }
}
