using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

internal readonly record struct RetentionCounts(int SecurityEvents, int Tokens);

public sealed class SecurityDataRetentionService : BackgroundService
{
    internal const int BatchSize = 500;
    internal const int MaxPerRun = 5000;
    internal static readonly TimeSpan Interval = TimeSpan.FromHours(24);
    private readonly IServiceScopeFactory scopeFactory;
    private readonly IOptions<AuthOptions> options;
    private readonly ILogger<SecurityDataRetentionService> logger;
    private readonly TimeProvider clock;
    public SecurityDataRetentionService(IServiceScopeFactory factory, IOptions<AuthOptions> options,
        ILogger<SecurityDataRetentionService> logger, TimeProvider clock)
        => (scopeFactory, this.options, this.logger, this.clock) = (factory, options, logger, clock);

    internal async Task<RetentionCounts> RunOnceAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value.Retention;
        settings.Validate();
        if (!settings.Enabled) return new(0, 0);
        cancellationToken.ThrowIfCancellationRequested();
        var now = clock.GetUtcNow().ToUniversalTime();
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var events = await PurgeEventsAsync(db, now.AddDays(-settings.SecurityEventRetentionDays), cancellationToken);
        var tokens = await PurgeTokensAsync(db, scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>(),
            now.AddDays(-settings.TokenRetentionDays).UtcDateTime, cancellationToken);
        return new(events, tokens);
    }

    internal async Task RunCycleAsync(CancellationToken cancellationToken)
    {
        try { await RunOnceAsync(cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception)
        {
            // No exception object/message: providers can include private SQL data.
            logger.LogWarning("Security retention cycle failed: {ErrorClass}", exception.GetType().Name);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        options.Value.Retention.Validate();
        if (!options.Value.Retention.Enabled) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            await RunCycleAsync(stoppingToken);
            try { await Task.Delay(Interval, clock, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private async Task<int> PurgeEventsAsync(PandaAuthDbContext db, DateTimeOffset cutoff, CancellationToken cancellationToken)
    {
        var removed = 0;
        var examined = 0;
        long? after = null;
        try
        {
            while (examined < MaxPerRun)
            {
                var query = db.SecurityEvents.AsNoTracking().Where(SecurityRetentionPolicy.EventsBefore(cutoff));
                if (after is { } cursor) query = query.Where(row => row.Id > cursor);
                var ids = await query.OrderBy(row => row.Id).Select(row => row.Id)
                    .Take(Math.Min(BatchSize, MaxPerRun - examined)).ToArrayAsync(cancellationToken);
                if (ids.Length == 0) break;
                examined += ids.Length;
                after = ids[^1];
                removed += await db.SecurityEvents.Where(row => ids.Contains(row.Id) && row.CreatedAt < cutoff)
                    .ExecuteDeleteAsync(cancellationToken);
            }
            return removed;
        }
        finally { logger.LogInformation("Security retention: SecurityEventsDeleted={Deleted}", removed); }
    }

    private async Task<int> PurgeTokensAsync(PandaAuthDbContext db, IOpenIddictTokenManager manager, DateTime cutoff, CancellationToken cancellationToken)
    {
        var removed = 0;
        var examined = 0;
        var conflicts = 0;
        string? after = null;
        try
        {
            while (examined < MaxPerRun)
            {
                var query = db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking()
                    .Where(SecurityRetentionPolicy.TokensBefore(cutoff));
                if (after is not null) query = query.Where(token => string.Compare(token.Id, after) > 0);
                var batch = await query.OrderBy(token => token.Id)
                    .Take(Math.Min(BatchSize, MaxPerRun - examined)).ToListAsync(cancellationToken);
                if (batch.Count == 0) break;
                examined += batch.Count;
                after = batch[^1].Id;
                foreach (var token in batch)
                {
                    try { await manager.DeleteAsync(token, cancellationToken); removed++; }
                    catch (Exception exception) when (exception is DbUpdateConcurrencyException or OpenIddictExceptions.ConcurrencyException)
                    {
                        db.Entry(token).State = EntityState.Detached;
                        conflicts++;
                    }
                }
            }
            return removed;
        }
        finally { logger.LogInformation("Security retention: TokensDeleted={Deleted} Conflicts={Conflicts}", removed, conflicts); }
    }
}
