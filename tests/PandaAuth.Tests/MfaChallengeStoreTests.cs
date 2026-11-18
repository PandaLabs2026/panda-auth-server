using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class MfaChallengeStoreTests
{
    [PostgresFact]
    public async Task ConcurrentConsumers_OnlyOneReceivesTheChallenge()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await using var firstContext = fixture.Context();
        await using var secondContext = fixture.Context();
        var first = new MfaChallengeStore(firstContext, TimeProvider.System);
        var second = new MfaChallengeStore(secondContext, TimeProvider.System);
        const string purpose = "pandesk-native-login-test";
        var challenge = await first.CreateAsync(purpose, fixture.UserId, [7], TimeSpan.FromMinutes(5), CancellationToken.None);

        var results = await Task.WhenAll(
            first.ConsumeAsync(challenge, purpose, fixture.UserId, CancellationToken.None),
            second.ConsumeAsync(challenge, purpose, fixture.UserId, CancellationToken.None));

        var consumed = Assert.Single(results.OfType<ConsumedMfaChallenge>());
        Assert.Equal(new byte[] { 7 }, consumed.Value);
        Assert.Null(await first.ConsumeAsync(challenge, purpose, fixture.UserId, CancellationToken.None));
    }

    [Fact]
    public async Task Challenge_CanOnlyBeConsumedOnceByItsBoundSubject()
    {
        await using var db = CreateDb();
        var store = new MfaChallengeStore(db, TimeProvider.System);
        var id = await store.CreateAsync("assert", "user-1", [9], TimeSpan.FromMinutes(5), CancellationToken.None);

        var first = await store.ConsumeAsync(id, "assert", "user-1", CancellationToken.None);
        var second = await store.ConsumeAsync(id, "assert", "user-1", CancellationToken.None);

        Assert.NotNull(first);
        Assert.Equal([9], first!.Value);
        Assert.Null(second);
    }

    [Fact]
    public async Task Challenge_BoundToAnotherSubjectOrPurpose_IsNotConsumed()
    {
        await using var db = CreateDb();
        var store = new MfaChallengeStore(db, TimeProvider.System);
        var id = await store.CreateAsync("enrollment", "user-1", [1], TimeSpan.FromMinutes(5), CancellationToken.None);

        Assert.Null(await store.ConsumeAsync(id, "enrollment", "user-2", CancellationToken.None));
        Assert.Null(await store.ConsumeAsync(id, "assert", "user-1", CancellationToken.None));

        var bound = await store.ConsumeAsync(id, "enrollment", "user-1", CancellationToken.None);
        Assert.NotNull(bound);
    }

    [Fact]
    public async Task ExpiredChallenge_IsNotConsumable()
    {
        await using var db = CreateDb();
        var id = Guid.NewGuid();
        db.MfaChallenges.Add(new MfaChallenge
        {
            Id = id,
            Purpose = "assert",
            SubjectId = "user-1",
            Value = [1],
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1),
        });
        await db.SaveChangesAsync();
        var store = new MfaChallengeStore(db, TimeProvider.System);

        Assert.Null(await store.ConsumeAsync(id, "assert", "user-1", CancellationToken.None));
    }

    [Fact]
    public async Task ReplacementChallenge_UsesTheOriginalAbsoluteDeadline()
    {
        await using var db = CreateDb();
        var deadline = new DateTimeOffset(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
        var ct = CancellationToken.None;
        var beforeExpiry = new MfaChallengeStore(db, new FixedClock(deadline.AddSeconds(-1)));

        var replacement = await beforeExpiry.TryCreateUntilAsync("assert", "user-1", [1], deadline, ct);

        Assert.NotNull(replacement);
        var challenge = await db.MfaChallenges.SingleAsync(ct);
        Assert.Equal(replacement, challenge.Id);
        Assert.Equal(deadline, challenge.ExpiresAt);

        var atExpiry = new MfaChallengeStore(db, new FixedClock(deadline));
        Assert.Null(await atExpiry.TryCreateUntilAsync("assert", "user-1", [1], deadline, ct));
        Assert.Null(await atExpiry.ConsumeAsync(challenge.Id, "assert", "user-1", ct));
        Assert.Single(await db.MfaChallenges.ToListAsync(ct));
    }

    private static PandaAuthDbContext CreateDb()
        => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
