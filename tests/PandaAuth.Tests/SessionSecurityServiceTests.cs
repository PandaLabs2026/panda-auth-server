using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SessionSecurityServiceTests
{
    [Fact]
    public async Task RequireCurrentUser_RejectsStaleStampAndInactiveAccount()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "session-user" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var sessions = provider.GetRequiredService<SessionSecurityService>();

        var valid = await sessions.RequireCurrentUserAsync(Principal(user));
        var stale = await sessions.RequireCurrentUserAsync(Principal(user, "stale"));
        user.Status = UserStatus.Frozen;
        Assert.True((await users.UpdateAsync(user)).Succeeded);
        var inactive = await sessions.RequireCurrentUserAsync(Principal(user));

        Assert.Equal(user.Id, valid!.Id);
        Assert.Null(stale);
        Assert.Null(inactive);
    }

    [Fact]
    public async Task InvalidateUser_RotatesStampRevokesTokensAndAuditsReason()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "invalidate-user" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var oldStamp = user.SecurityStamp;
        var revoker = new RecordingTokenRevoker();
        provider.GetRequiredService<PandaAuthDbContext>().Database.EnsureCreated();
        var service = new SessionSecurityService(
            users,
            revoker,
            provider.GetRequiredService<SecurityEventWriter>());

        var result = await service.InvalidateUserAsync(user, "password_changed", user.Id);

        Assert.True(result.Succeeded);
        Assert.NotEqual(oldStamp, user.SecurityStamp);
        Assert.Equal(user.Id, revoker.LastUserId);
        var audit = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents);
        Assert.Equal("session.invalidated", audit.EventType);
        Assert.Contains("password_changed", audit.Metadata);
    }

    [Fact]
    public async Task RevokeUserAuthorizations_DelegatesToTokenRevoker()
    {
        using var provider = TestUserStoreHost.Create();
        var revoker = new RecordingTokenRevoker();
        var service = new SessionSecurityService(
            provider.GetRequiredService<UserService>(), revoker);

        await service.RevokeUserAuthorizationsAsync("user-1", "client-1");

        Assert.Equal("user-1", revoker.LastUserId);
        Assert.Equal("client-1", revoker.LastClientId);
    }

    private static ClaimsPrincipal Principal(PandaUser user, string? stamp = null)
        => new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(LoginSessionService.StampClaim, stamp ?? user.SecurityStamp!),
            ], LoginSessionService.Scheme));

    private sealed class RecordingTokenRevoker : ITokenRevoker
    {
        public string? LastUserId { get; private set; }
        public string? LastClientId { get; private set; }

        public Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
        {
            LastUserId = userId;
            LastClientId = clientId;
            return Task.CompletedTask;
        }

        public Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
