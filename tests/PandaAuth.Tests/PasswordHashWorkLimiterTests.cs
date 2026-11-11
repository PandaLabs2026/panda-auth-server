using Microsoft.AspNetCore.Http;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PasswordHashWorkLimiterTests
{
    [Fact]
    public async Task Third_hash_waits_until_an_active_hash_finishes()
    {
        using var limiter = new PasswordHashWorkLimiter(new HttpContextAccessor());
        using var first = await limiter.AcquireAsync(19456);
        using var second = await limiter.AcquireAsync(19456);
        var pending = limiter.AcquireAsync(19456).AsTask();
        Assert.False(pending.IsCompleted);
        first.Dispose();
        using var third = await pending.WaitAsync(TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task Memory_budget_serializes_larger_legacy_hashes()
    {
        using var limiter = new PasswordHashWorkLimiter(new HttpContextAccessor());
        using var first = await limiter.AcquireAsync(49152);
        var pending = limiter.AcquireAsync(32768).AsTask();
        Assert.False(pending.IsCompleted);
        first.Dispose();
        using var second = await pending.WaitAsync(TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task Queue_overflow_is_rejected_and_canceled_waiters_release_capacity()
    {
        using var limiter = new PasswordHashWorkLimiter(new HttpContextAccessor());
        using var first = await limiter.AcquireAsync(19456);
        using var second = await limiter.AcquireAsync(19456);
        using var cancel = new CancellationTokenSource();
        var queued = Enumerable.Range(0, 32).Select(_ => limiter.AcquireAsync(19456, cancel.Token).AsTask()).ToArray();
        try
        {
            Assert.All(queued, task => Assert.False(task.IsCompleted));
            await Assert.ThrowsAsync<PasswordHashCapacityException>(() => limiter.AcquireAsync(19456).AsTask());
        }
        finally
        {
            cancel.Cancel();
            foreach (var task in queued)
            {
                try { (await task).Dispose(); } catch (OperationCanceledException) { }
            }
        }
        first.Dispose(); second.Dispose();
        using var recovered = await limiter.AcquireAsync(19456);
    }

    [Fact]
    public async Task Cancellation_while_waiting_for_memory_does_not_leak_a_work_slot()
    {
        using var limiter = new PasswordHashWorkLimiter(new HttpContextAccessor());
        using var large = await limiter.AcquireAsync(49152);
        using var cancel = new CancellationTokenSource();
        var pending = limiter.AcquireAsync(32768, cancel.Token).AsTask();
        Assert.False(pending.IsCompleted);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        using var small = await limiter.AcquireAsync(8192).AsTask().WaitAsync(TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task Unserviceable_memory_cost_is_busy_rather_than_an_invalid_password()
    {
        using var limiter = new PasswordHashWorkLimiter(new HttpContextAccessor());
        await Assert.ThrowsAsync<PasswordHashCapacityException>(() => limiter.AcquireAsync(65537).AsTask());
        using var supported = await limiter.AcquireAsync(65536);
    }

    [Fact]
    public async Task Queue_deadline_returns_busy_and_releases_the_waiter()
    {
        using var limiter = new PasswordHashWorkLimiter(new HttpContextAccessor());
        using var first = await limiter.AcquireAsync(19456);
        using var second = await limiter.AcquireAsync(19456);
        await Assert.ThrowsAsync<PasswordHashCapacityException>(() =>
            limiter.AcquireAsync(19456).AsTask().WaitAsync(TimeSpan.FromSeconds(15)));
        first.Dispose(); second.Dispose();
        using var recovered = await limiter.AcquireAsync(19456);
    }
}
