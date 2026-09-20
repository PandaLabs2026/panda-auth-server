using Microsoft.Extensions.Caching.Memory;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class MfaChallengeStoreTests
{
    [Fact]
    public async Task Challenge_CanOnlyBeConsumedOnceByItsBoundSubject()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new MfaChallengeStore(cache, TimeProvider.System);
        var id = await store.CreateAsync("assert", "user-1", [9], TimeSpan.FromMinutes(5), CancellationToken.None);

        Assert.NotNull(await store.ConsumeAsync(id, "assert", "user-1", CancellationToken.None));
        Assert.Null(await store.ConsumeAsync(id, "assert", "user-1", CancellationToken.None));
    }

    [Fact]
    public async Task Challenge_BoundToAnotherSubject_IsNotConsumed()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new MfaChallengeStore(cache, TimeProvider.System);
        var id = await store.CreateAsync("assert", "user-1", [9], TimeSpan.FromMinutes(5), CancellationToken.None);

        Assert.Null(await store.ConsumeAsync(id, "assert", "user-2", CancellationToken.None));
        Assert.NotNull(await store.ConsumeAsync(id, "assert", "user-1", CancellationToken.None));
    }
}
