using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class SecurityRetentionPostgresTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 0, 0, 0, TimeSpan.Zero);

    [PostgresFact]
    public async Task ActualDatabase_PreservesBoundariesReplayTimesAndAuthorizations()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            db.SecurityEvents.AddRange(new SecurityEvent { EventType = "quality.retention", CreatedAt = Now.AddDays(-90).AddSeconds(-1) },
                new SecurityEvent { EventType = "quality.retention", CreatedAt = Now.AddDays(-90) },
                new SecurityEvent { EventType = "quality.retention", CreatedAt = Now });
            var authorization = new OpenIddictEntityFrameworkCoreAuthorization
            { Id = "quality-authorization", Status = Statuses.Valid, Type = AuthorizationTypes.Permanent, Subject = "fixture-user" };
            db.Add(authorization);
            var expired = OldToken("expired"); expired.Authorization = authorization;
            var redeemed = OldToken("old-redeemed"); redeemed.Status = Statuses.Redeemed; redeemed.RedemptionDate = Now.AddDays(-15).UtcDateTime;
            var unexpired = OldToken("unexpired"); unexpired.Status = Statuses.Revoked; unexpired.ExpirationDate = Now.AddDays(1).UtcDateTime;
            var missingCreation = OldToken("missing-creation"); missingCreation.CreationDate = null;
            var missingExpiry = OldToken("missing-expiry"); missingExpiry.ExpirationDate = null;
            var missingRedemption = OldToken("missing-redemption"); missingRedemption.Status = Statuses.Redeemed;
            var freshRedemption = OldToken("fresh-redemption"); freshRedemption.Status = Statuses.Redeemed; freshRedemption.RedemptionDate = Now.UtcDateTime;
            var boundary = OldToken("boundary"); boundary.ExpirationDate = Now.AddDays(-14).UtcDateTime;
            db.AddRange(expired, redeemed, unexpired, missingCreation, missingExpiry, missingRedemption, freshRedemption, boundary);
            await db.SaveChangesAsync();
        }
        Assert.Equal(new RetentionCounts(1, 2), await Service(fixture).RunOnceAsync(CancellationToken.None));
        await using var check = fixture.Services.CreateAsyncScope();
        var current = check.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(2, await current.SecurityEvents.CountAsync());
        Assert.Equal(6, await current.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync());
        Assert.Equal(1, await current.Set<OpenIddictEntityFrameworkCoreAuthorization>().CountAsync());
    }

    [PostgresFact]
    public async Task EachCategory_StopsAtFiveThousand_AndNextRunContinues()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            db.SecurityEvents.AddRange(Enumerable.Range(0, 5001).Select(_ => new SecurityEvent
                { EventType = "quality.retention", CreatedAt = Now.AddDays(-91) }));
            db.AddRange(Enumerable.Range(0, 5001).Select(index => OldToken("bounded-" + index.ToString("D6"))));
            await db.SaveChangesAsync();
        }
        var service = Service(fixture);
        Assert.Equal(new RetentionCounts(5000, 5000), await service.RunOnceAsync(CancellationToken.None));
        Assert.Equal(new RetentionCounts(1, 1), await service.RunOnceAsync(CancellationToken.None));
    }

    [PostgresFact]
    public async Task ConcurrentRedemption_IsRetainedByManagerConcurrencyChecks()
    {
        var interceptor = new BeforeTokenDelete();
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(interceptor);
        await AddOldTokenAsync(fixture);
        interceptor.Action = async () =>
        {
            await using var scope = fixture.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var token = await db.Set<OpenIddictEntityFrameworkCoreToken>().SingleAsync();
            token.Status = Statuses.Redeemed;
            token.RedemptionDate = Now.UtcDateTime;
            token.ConcurrencyToken = Guid.NewGuid().ToString();
            await db.SaveChangesAsync();
        };
        Assert.Equal(new RetentionCounts(0, 0), await Service(fixture).RunOnceAsync(CancellationToken.None));
        Assert.True(interceptor.Triggered);
        await using var check = fixture.Services.CreateAsyncScope();
        Assert.Equal(Now.UtcDateTime, (await check.ServiceProvider.GetRequiredService<PandaAuthDbContext>()
            .Set<OpenIddictEntityFrameworkCoreToken>().SingleAsync()).RedemptionDate);
    }

    [PostgresFact]
    public async Task DeleteFailure_DoesNotLoseToken_AndLaterCycleRetries()
    {
        var interceptor = new BeforeTokenDelete { Action = () => throw new InvalidOperationException("fixture-secret-sentinel") };
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(interceptor);
        await AddOldTokenAsync(fixture);
        var service = Service(fixture);
        await service.RunCycleAsync(CancellationToken.None);
        Assert.True(interceptor.Triggered);
        interceptor.Action = null;
        Assert.Equal(new RetentionCounts(0, 1), await service.RunOnceAsync(CancellationToken.None));
    }

    private static async Task AddOldTokenAsync(AuthQualityPostgresFixture fixture)
    {
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        db.Add(OldToken("single-token"));
        await db.SaveChangesAsync();
    }

    private static OpenIddictEntityFrameworkCoreToken OldToken(string id) => new()
    {
        Id = id, ConcurrencyToken = Guid.NewGuid().ToString(), Subject = "fixture-user",
        Status = Statuses.Valid, Type = TokenTypeHints.AccessToken,
        CreationDate = Now.AddDays(-20).UtcDateTime, ExpirationDate = Now.AddDays(-15).UtcDateTime,
    };

    private static SecurityDataRetentionService Service(AuthQualityPostgresFixture fixture)
    {
        var options = new AuthOptions(); options.Retention.Enabled = true;
        return new(fixture.Services.GetRequiredService<IServiceScopeFactory>(), Options.Create(options),
            NullLogger<SecurityDataRetentionService>.Instance, new FixedClock());
    }

    private sealed class FixedClock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class BeforeTokenDelete : SaveChangesInterceptor
    {
        internal Func<Task>? Action;
        internal bool Triggered;
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!Triggered && Action is not null && eventData.Context!.ChangeTracker.Entries<OpenIddictEntityFrameworkCoreToken>()
                    .Any(entry => entry.State == EntityState.Deleted))
            {
                Triggered = true;
                await Action();
            }
            return await base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }
}
