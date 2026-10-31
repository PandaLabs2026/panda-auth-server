using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>Joins an account operation's existing transaction, otherwise owns its commit and rollback.</summary>
internal sealed class AccountSecurityTransaction(PandaAuthDbContext db, IDbContextTransaction? owned) : IAsyncDisposable
{
    private bool committed;

    internal static async Task<AccountSecurityTransaction> BeginAsync(PandaAuthDbContext db, CancellationToken cancellationToken = default)
        => new(db, db.Database.IsRelational() && db.Database.CurrentTransaction is null
            ? await db.Database.BeginTransactionAsync(cancellationToken) : null);

    internal static async Task LockUserAsync(PandaAuthDbContext db, string userId, CancellationToken cancellationToken)
    {
        // Serialize TOTP enrollment/proofs and administrative reset before reading factors.
        // The user row also exists before the first factor, unlike a factor-only lock.
        if (db.Database.IsRelational())
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT 1 FROM panda_users WHERE \"Id\" = {userId} FOR UPDATE", cancellationToken);
    }

    internal async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        if (owned is not null) await owned.CommitAsync(cancellationToken);
        committed = true;
    }

    public async ValueTask DisposeAsync()
    {
        if (owned is null) return;
        try { await owned.DisposeAsync(); }
        finally { if (!committed) db.ChangeTracker.Clear(); }
    }
}
