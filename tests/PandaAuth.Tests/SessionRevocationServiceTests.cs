using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.SessionState;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SessionRevocationServiceTests
{
    [Fact]
    public async Task Shared_login_revocation_is_distinct_from_local_sessions_and_other_devices()
    {
        await using var db = CreateDatabase();
        var service = new SessionRevocationService(db, new TestClock(DateTimeOffset.UtcNow));
        await service.RevokeAsync("sso-session", "login-device-a", CancellationToken.None);
        Assert.True(await service.IsRevokedAsync("sso-session", "login-device-a", CancellationToken.None));
        Assert.False(await service.IsRevokedAsync("sso-session", "login-device-b", CancellationToken.None));
        Assert.False(await service.IsRevokedAsync("admin-session-api", "login-device-a", CancellationToken.None));
        Assert.False(await service.IsRevokedAsync("me-session-api", "login-device-a", CancellationToken.None));
    }

    [Fact]
    public async Task Revocation_is_idempotent_scoped_to_client_and_stores_only_a_hash()
    {
        var clock = new TestClock(DateTimeOffset.Parse("2026-10-19T12:00:00Z"));
        await using var db = CreateDatabase();
        var service = new SessionRevocationService(db, clock);

        await service.RevokeAsync("admin-session-api", "opaque-session-id", CancellationToken.None);
        await service.RevokeAsync("admin-session-api", "opaque-session-id", CancellationToken.None);

        Assert.True(await service.IsRevokedAsync("admin-session-api", "opaque-session-id", CancellationToken.None));
        Assert.False(await service.IsRevokedAsync("me-session-api", "opaque-session-id", CancellationToken.None));
        var row = await db.SessionRevocations.SingleAsync();
        Assert.DoesNotContain("opaque-session-id", row.SessionIdHash, StringComparison.Ordinal);
        Assert.Equal(clock.GetUtcNow().AddHours(2), row.ExpiresAt);
    }

    [Fact]
    public async Task Expired_revocation_is_not_active()
    {
        var clock = new TestClock(DateTimeOffset.Parse("2026-10-19T12:00:00Z"));
        await using var db = CreateDatabase();
        var service = new SessionRevocationService(db, clock);

        await service.RevokeAsync("me-session-api", "session-1", CancellationToken.None);
        clock.Advance(TimeSpan.FromHours(8).Add(TimeSpan.FromTicks(1)));

        Assert.False(await service.IsRevokedAsync("me-session-api", "session-1", CancellationToken.None));
    }

    [Fact]
    public async Task Unknown_client_cannot_create_or_query_revocations()
    {
        await using var db = CreateDatabase();
        var service = new SessionRevocationService(db, new TestClock(DateTimeOffset.UtcNow));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.RevokeAsync("mgmt-api", "session-1", CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.IsRevokedAsync("mgmt-api", "session-1", CancellationToken.None));
    }

    private static PandaAuthDbContext CreateDatabase()
    {
        var options = new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options;
        return new PandaAuthDbContext(options);
    }

    private sealed class TestClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
