using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ProfileContactRetentionTests
{
    [Fact]
    public async Task Disabled_feature_never_opens_a_database_scope()
    {
        using var services = new ServiceCollection().BuildServiceProvider();
        using var worker = new ProfileContactRetention(services.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new ProfileOptions()), TimeProvider.System, NullLogger<ProfileContactRetention>.Instance);
        Assert.Equal(0, await worker.RunOnceAsync(default));
    }

    [PostgresFact]
    public async Task Expired_proof_material_is_purged_in_bounded_batches_without_resetting_account_limits()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        var now = DateTimeOffset.UtcNow;
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var user = new PandaUser(); db.Users.Add(user);
            db.UserProfiles.Add(new UserProfile { UserId = user.Id, Revision = new string('a', 32) });
            db.ProfileRateLimits.Add(new ProfileRateLimit { UserId = user.Id, CreationCount = 5, CreationWindowStart = now });
            for (var i = 0; i < 502; i++) db.ProfileContactChallenges.Add(new ProfileContactChallenge
            {
                Id = Guid.NewGuid(), UserId = user.Id, Address = "private@example.invalid", TokenDigest = new byte[32],
                ExpectedRevision = new string('a', 32), DeliveryId = Guid.NewGuid(), State = ProfileContactChallengeState.Superseded,
                CreatedAt = now.AddMinutes(-11), ExpiresAt = i == 501 ? now.AddHours(1) : now.AddMinutes(-1),
            });
            await db.SaveChangesAsync();
        }
        using var worker = new ProfileContactRetention(fixture.Services.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new ProfileOptions { Enabled = true }), TimeProvider.System, NullLogger<ProfileContactRetention>.Instance);
        Assert.Equal(500, await worker.RunOnceAsync(default));
        Assert.Equal(1, await worker.RunOnceAsync(default));
        await using var check = fixture.Services.CreateAsyncScope();
        var current = check.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Single(await current.ProfileContactChallenges.ToListAsync());
        Assert.Equal(5, (await current.ProfileRateLimits.SingleAsync()).CreationCount);
    }
}
