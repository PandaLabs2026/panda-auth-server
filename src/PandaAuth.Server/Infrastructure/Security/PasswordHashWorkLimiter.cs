using System.Threading.RateLimiting;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed class PasswordHashCapacityException : Exception
{
    public PasswordHashCapacityException() : base("Password work capacity is unavailable.") { }
}

/// <summary>Per-host admission for expensive password work, shared by every scoped hasher.</summary>
public sealed class PasswordHashWorkLimiter(IHttpContextAccessor accessor) : IDisposable
{
    private const int MemoryBudgetKiB = 65536;
    private readonly ConcurrencyLimiter workers = new(new ConcurrencyLimiterOptions
    {
        PermitLimit = 1, QueueLimit = 32, QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
    });
    private readonly ConcurrencyLimiter memory = new(new ConcurrencyLimiterOptions
    {
        PermitLimit = MemoryBudgetKiB, QueueLimit = MemoryBudgetKiB * 2,
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
    });

    public async ValueTask<IDisposable> AcquireAsync(int memoryKiB, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(memoryKiB);
        var aborted = accessor.HttpContext?.RequestAborted ?? CancellationToken.None;
        cancellationToken.ThrowIfCancellationRequested();
        aborted.ThrowIfCancellationRequested();
        // Larger imported hashes need a separate host budget, not a cheaper password calculation.
        if (memoryKiB > MemoryBudgetKiB) throw new PasswordHashCapacityException();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, aborted);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        RateLimitLease? worker = null;
        RateLimitLease? reservation = null;
        try
        {
            worker = await workers.AcquireAsync(1, deadline.Token).ConfigureAwait(false);
            if (!worker.IsAcquired) throw new PasswordHashCapacityException();
            reservation = await memory.AcquireAsync(memoryKiB, deadline.Token).ConfigureAwait(false);
            if (!reservation.IsAcquired) throw new PasswordHashCapacityException();
            var lease = new WorkLease(worker, reservation);
            worker = null; reservation = null;
            return lease;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && !aborted.IsCancellationRequested)
        {
            throw new PasswordHashCapacityException();
        }
        finally
        {
            reservation?.Dispose();
            worker?.Dispose();
        }
    }

    public void Dispose()
    {
        workers.Dispose();
        memory.Dispose();
    }

    private sealed class WorkLease(RateLimitLease worker, RateLimitLease reservation) : IDisposable
    {
        private int disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            reservation.Dispose();
            worker.Dispose();
        }
    }
}
