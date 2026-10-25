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
