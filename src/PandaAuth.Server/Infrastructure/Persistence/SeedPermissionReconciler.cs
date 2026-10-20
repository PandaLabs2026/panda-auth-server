using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Infrastructure.Persistence;

internal sealed class SeedPermissionReconciler(
    IOpenIddictApplicationManager applications, SeedOptions options,
    PandaAuthDbContext? db, ILogger? logger, TimeProvider clock)
{
    internal async Task<bool> ApplyAsync(object application, IEnumerable<string> expected)
    {
        var clientId = await applications.GetClientIdAsync(application)
            ?? throw new InvalidOperationException("Seed application has no client ID.");
        var current = await applications.GetPermissionsAsync(application);
        var desired = expected.ToArray();
        var change = SeedPermissionPolicy.Plan(current, desired, options, clientId);
        var surplus = current.Except(desired, StringComparer.Ordinal).Count();
        if (surplus > 0)
            logger?.LogInformation("Seed permission reconciliation: client={ClientId} surplus={Surplus} plannedRemoved={PlannedRemoved}", clientId, surplus, change.Removed.Length);
        if (change.Added.Length == 0 && change.Removed.Length == 0) return false;

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application);
        descriptor.Permissions.Clear();
        descriptor.Permissions.UnionWith(change.Target);

        async Task UpdateAsync()
        {
            // Populate roundtrip preserves the existing hash. The secret-taking
            // UpdateAsync overload is deliberately not used for permissions.
            await applications.PopulateAsync(application, descriptor);
            await applications.UpdateAsync(application);
        }

        if (change.Removed.Length == 0)
        {
            await UpdateAsync();
            return true;
        }
        if (db is null || !db.Database.IsRelational())
            throw new InvalidOperationException("Exact permission removal requires a relational transaction.");

        await using var transaction = await db.Database.BeginTransactionAsync();
        try
        {
            await UpdateAsync();
            var events = new SecurityEventWriter(db, clock);
            await new TokenRevocationService(db, events).RevokeClientTokensAsync(clientId);
            await events.RecordAsync(new SecurityEventEntry(
                "seed.client_permissions_reconciled", null, null, "client", clientId,
                "seed_exact", new { added = change.Added.Length, removed = change.Removed.Length },
                null, null, null));
            await transaction.CommitAsync();
        }
        catch
        {
            await transaction.RollbackAsync();
            await transaction.DisposeAsync();
            // A manager may cache the entity instance that Populate changed.
            // Reload it after rollback as well as clearing failed audit tracking.
            db.ChangeTracker.Clear();
            await db.Entry(application).ReloadAsync();
            throw;
        }
        return true;
    }
}
