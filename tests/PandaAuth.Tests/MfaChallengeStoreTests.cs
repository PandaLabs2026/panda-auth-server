using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class MfaChallengeStoreTests
{
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

    private static PandaAuthDbContext CreateDb()
        => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);
}
