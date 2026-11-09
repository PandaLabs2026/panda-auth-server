using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Features.Profile;

/// <summary>Proof material has no use after its ten-minute lifetime. Security audit follows its separate policy.</summary>
public sealed class ProfileContactRetention(IServiceScopeFactory scopes, IOptions<ProfileOptions> options,
    TimeProvider clock, ILogger<ProfileContactRetention> logger) : BackgroundService
{
    internal async Task<int> RunOnceAsync(CancellationToken ct)
    {
        if (!options.Value.Enabled) return 0;
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var now = clock.GetUtcNow();
        var ids = await db.ProfileContactChallenges.AsNoTracking().Where(c => c.ExpiresAt <= now)
            .OrderBy(c => c.ExpiresAt).ThenBy(c => c.Id).Select(c => c.Id).Take(500).ToArrayAsync(ct);
        return await db.ProfileContactChallenges.Where(c => ids.Contains(c.Id) && c.ExpiresAt <= now).ExecuteDeleteAsync(ct);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunOnceAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error)
            {
                // Provider exceptions can include private SQL values; record only the class.
                logger.LogWarning("Profile contact cleanup failed class={ErrorClass}", error.GetType().Name);
            }
            try { await Task.Delay(TimeSpan.FromMinutes(1), clock, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
