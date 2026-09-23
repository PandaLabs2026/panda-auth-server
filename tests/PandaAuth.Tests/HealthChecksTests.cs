using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public class HealthChecksTests
{
    [Fact]
    public async Task DbContextCheck_ReportsHealthyWhenDatabaseReachable()
    {
        // /healthz 的生产装配是 AddDbContextCheck<PandaAuthDbContext>（Program.cs）：
        // 这里用同款装配 + InMemory 底座验证「检查真正执行且可达即 Healthy」，
        // 防止包/注册路径断裂退化回空检查的假绿。
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PandaAuthDbContext>(options =>
            options.UseInMemoryDatabase($"health-{Guid.NewGuid():N}"));
        services.AddHealthChecks().AddDbContextCheck<PandaAuthDbContext>();

        using var provider = services.BuildServiceProvider();
        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();

        Assert.Equal(HealthStatus.Healthy, report.Status);
        Assert.Contains(report.Entries, entry => entry.Value.Status == HealthStatus.Healthy);    }
}
