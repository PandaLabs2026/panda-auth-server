using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.ReadinessHarness;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class FixtureRecoveryStateTests
{
    [Fact]
    public async Task RecoveryFixtureContainsUsableAndConsumedCodesAndNonemptyAudits()
    {
        using var provider = TestUserStoreHost.Create();
        var settings = new LoadRequest { RunId = new string('c', 32), BaseUri = "https://localhost:39001/",
            RootCertificateFile = "fixture.pem", Password = "synthetic-only", ClientSecret = "synthetic-only",
            Workload = "cookie", Concurrency = 1, DurationSeconds = 3, RecoveryScenario = true,
            RecoveryTotpKey = Convert.ToBase64String(new byte[32]) };
        var administrator = new PandaUser { UserName = settings.AdminUserName, Email = settings.AdminUserName,
            EmailConfirmed = true, TwoFactorEnabled = true };
        var users = provider.GetRequiredService<UserService>();
        Assert.True((await users.CreateAsync(administrator, "Fixture!Password123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor { Id = Guid.NewGuid(), UserId = administrator.Id, ConfirmedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        await FixtureRecoveryState.PopulateAsync(db, users, provider.GetRequiredService<LoginSessionService>(), settings, administrator);
        Assert.Equal(9, await db.MfaRecoveryCodes.CountAsync(row => row.ConsumedAt == null));
        Assert.Equal(1, await db.MfaRecoveryCodes.CountAsync(row => row.ConsumedAt != null));
        Assert.Equal(1, await db.MfaRecoveryEvents.CountAsync(row => row.Reason != MfaRecoveryEvent.AdminResetReason));
        Assert.Equal(1, await db.AdminAuditLogs.CountAsync());
    }
}
