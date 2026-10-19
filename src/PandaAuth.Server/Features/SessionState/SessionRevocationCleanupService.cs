using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace PandaAuth.Server.Features.SessionState;

public sealed class SessionRevocationCleanupService(
    IServiceScopeFactory scopeFactory,
    ILogger<SessionRevocationCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var service = scope.ServiceProvider.GetRequiredService<SessionRevocationService>();
                var deleted = await service.DeleteExpiredBatchAsync(stoppingToken);
                if (deleted > 0) logger.LogInformation("Removed {Count} expired session revocation records.", deleted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Session revocation cleanup failed.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
