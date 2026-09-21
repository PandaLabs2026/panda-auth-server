using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public class UserStoreTests
{
    [Fact]
    public async Task NormalizedNamesAndEmailsAreUnique_AndIdsArePreserved()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { Id = "legacy-id", UserName = "Alice", Email = "Alice@example.com" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        Assert.Equal("legacy-id", (await users.FindByNameAsync("aLiCe"))!.Id);
        Assert.Equal("legacy-id", (await users.FindByEmailAsync("ALICE@EXAMPLE.COM"))!.Id);
        Assert.False((await users.CreateAsync(new PandaUser { UserName = "ALICE" })).Succeeded);
        Assert.False((await users.CreateAsync(new PandaUser { UserName = "Other", Email = "alice@example.com" })).Succeeded);
    }

    [Fact]
    public async Task PasswordReplacementIsAtomic_AndRotatesSecurityStampOnlyOnSuccess()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "alice" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var hash = user.PasswordHash;
        var stamp = user.SecurityStamp;
        Assert.False((await users.ReplacePasswordAsync(user, "weak")).Succeeded);
        Assert.Equal(hash, user.PasswordHash);
        Assert.Equal(stamp, user.SecurityStamp);
        Assert.True((await users.ReplacePasswordAsync(user, "NewStrong!Pass123")).Succeeded);
        Assert.NotEqual(stamp, user.SecurityStamp);
        Assert.False(await users.CheckPasswordAsync(user, "Strong!Pass123"));
        Assert.True(await users.CheckPasswordAsync(user, "NewStrong!Pass123"));
    }

    [Fact]
    public async Task FiveFailuresLockAccount_AndSuccessfulLoginClearsFailures()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var sessions = provider.GetRequiredService<LoginSessionService>();
        var user = new PandaUser { UserName = "alice" };
        await users.CreateAsync(user, "Strong!Pass123");
        for (var i = 0; i < 4; i++)
            Assert.False((await sessions.CheckPasswordSignInAsync(user, "wrong", true)).IsLockedOut);
        Assert.True((await sessions.CheckPasswordSignInAsync(user, "wrong", true)).IsLockedOut);
        Assert.False((await sessions.CheckPasswordSignInAsync(user, "Strong!Pass123", true)).Succeeded);
        await users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(-1));
        Assert.True((await sessions.CheckPasswordSignInAsync(user, "Strong!Pass123", true)).Succeeded);
        Assert.Equal(0, user.AccessFailedCount);
    }

    [Fact]
    public async Task StaleUserUpdateFailsWithoutOverwritingNewPassword()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "alice" };
        await users.CreateAsync(user, "Strong!Pass123");
        using var scope = provider.CreateScope();
        var other = scope.ServiceProvider.GetRequiredService<UserService>();
        var stale = (await other.FindByIdAsync(user.Id))!;
        await users.ReplacePasswordAsync(user, "NewStrong!Pass123");
        stale.Nickname = "stale update";
        Assert.False((await other.UpdateAsync(stale)).Succeeded);
        using var check = provider.CreateScope();
        var saved = await check.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Users.SingleAsync();
        Assert.Equal(user.PasswordHash, saved.PasswordHash);
    }

    [Fact]
    public async Task ConcurrentLoginReturnsTheReloadedUserForAnImmediatePasswordChange()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "alice" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);

        using var scope = provider.CreateScope();
        var concurrentUsers = scope.ServiceProvider.GetRequiredService<UserService>();
        var sessions = scope.ServiceProvider.GetRequiredService<LoginSessionService>();
        var stale = (await concurrentUsers.FindByIdAsync(user.Id))!;

        user.Nickname = "concurrent change";
        Assert.True((await users.UpdateAsync(user)).Succeeded);

        var login = await sessions.CheckPasswordSignInAsync(stale, "Strong!Pass123", lockoutOnFailure: true);

        Assert.True(login.Succeeded);
        Assert.NotNull(login.User);
        Assert.True((await concurrentUsers.ReplacePasswordAsync(login.User!, "NewStrong!Pass123")).Succeeded);
        Assert.True((await concurrentUsers.UpdateSecurityStampAsync(login.User!)).Succeeded);
    }

    [Fact]
    public async Task AccountAwaitingMfaReconfigurationCannotCompletePasswordSignIn()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var sessions = provider.GetRequiredService<LoginSessionService>();
        var user = new PandaUser { UserName = "mfa-user", TwoFactorEnabled = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);

        var login = await sessions.CheckPasswordSignInAsync(user, "Strong!Pass123", lockoutOnFailure: true);

        Assert.False(login.Succeeded);
        Assert.True(login.IsNotAllowed);
        Assert.True(login.RequiresMfaReconfiguration);
    }
}
