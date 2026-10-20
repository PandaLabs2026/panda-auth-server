using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class SeedPermissionPostgresTests
{
    [PostgresFact]
    public async Task Exact_AdditionsOnly_DoNotRevokeOrAuditRemoval()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await ApplicationAsync(manager, db);
        var hash = app.ClientSecret;
        var reconciler = new SeedPermissionReconciler(manager, Exact(), db, null, TimeProvider.System);
        Assert.True(await reconciler.ApplyAsync(app, [Permissions.Endpoints.Token, Permissions.Endpoints.Introspection, Permissions.Endpoints.Revocation]));
        Assert.Equal(hash, app.ClientSecret);
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync(token => token.Status == Statuses.Valid));
        Assert.Empty(await db.SecurityEvents.ToListAsync());
    }

    [PostgresFact]
    public async Task AddMissing_PreservesSurplusHashAndValidTokens()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await ApplicationAsync(manager, db);
        var hash = app.ClientSecret;
        var reconciler = new SeedPermissionReconciler(manager, new SeedOptions(), db, null, TimeProvider.System);
        Assert.True(await reconciler.ApplyAsync(app, [Permissions.Endpoints.Token, Permissions.Endpoints.Revocation]));
        Assert.Contains(Permissions.Endpoints.Introspection, await manager.GetPermissionsAsync(app));
        Assert.Contains(Permissions.Endpoints.Revocation, await manager.GetPermissionsAsync(app));
        Assert.Equal(hash, app.ClientSecret);
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync(token => token.Status == Statuses.Valid));
        Assert.Empty(await db.SecurityEvents.ToListAsync());
    }

    [PostgresFact]
    public async Task Exact_RemovesRevokesAuditsAtomically_AndIsIdempotent()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await ApplicationAsync(manager, db);
        var hash = app.ClientSecret;
        var reconciler = new SeedPermissionReconciler(manager, Exact(), db, null, TimeProvider.System);
        Assert.True(await reconciler.ApplyAsync(app, [Permissions.Endpoints.Token]));
        Assert.Equal(new[] { Permissions.Endpoints.Token }, await manager.GetPermissionsAsync(app));
        Assert.Equal(hash, app.ClientSecret);
        Assert.False(await db.Set<OpenIddictEntityFrameworkCoreToken>().AnyAsync(token => token.Status == Statuses.Valid));
        Assert.Equal(2, await db.SecurityEvents.CountAsync());
        Assert.False(await reconciler.ApplyAsync(app, [Permissions.Endpoints.Token]));
        Assert.Equal(2, await db.SecurityEvents.CountAsync());
    }

    [PostgresFact]
    public async Task FailedAudit_RollsBackPermissionsTokensAndAudit_AndRestoresCachedEntity()
    {
        var failure = new AuditFailure();
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(failure);
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await ApplicationAsync(manager, db);
        var hash = app.ClientSecret;
        failure.Enabled = true;
        var reconciler = new SeedPermissionReconciler(manager, Exact(), db, null, TimeProvider.System);
        await Assert.ThrowsAsync<InjectedAuditFailure>(() => reconciler.ApplyAsync(app, [Permissions.Endpoints.Token]));
        Assert.Contains(Permissions.Endpoints.Introspection, await manager.GetPermissionsAsync(app));
        Assert.Equal(hash, app.ClientSecret);
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking().CountAsync(token => token.Status == Statuses.Valid));
        Assert.Empty(await db.SecurityEvents.AsNoTracking().ToListAsync());
        var persisted = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync();
        Assert.Contains(Permissions.Endpoints.Introspection, await manager.GetPermissionsAsync(persisted));
    }

    private static SeedOptions Exact() => new()
    {
        PermissionReconciliationMode = SeedPermissionReconciliationMode.Exact,
        ExactPermissionClientIds = [FirstPartyClients.MeWeb],
    };

    private static async Task<OpenIddictEntityFrameworkCoreApplication> ApplicationAsync(IOpenIddictApplicationManager manager, PandaAuthDbContext db)
    {
        var app = (OpenIddictEntityFrameworkCoreApplication)await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = FirstPartyClients.MeWeb, ClientType = ClientTypes.Confidential,
            ClientSecret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
            Permissions = { Permissions.Endpoints.Token, Permissions.Endpoints.Introspection },
        });
        db.Set<OpenIddictEntityFrameworkCoreToken>().Add(new OpenIddictEntityFrameworkCoreToken
        {
            Id = Guid.NewGuid().ToString(), Application = app, Subject = "fixture-user",
            Status = Statuses.Valid, Type = TokenTypeHints.AccessToken,
            CreationDate = DateTime.UtcNow.AddDays(-1), ExpirationDate = DateTime.UtcNow.AddDays(1),
        });
        await db.SaveChangesAsync();
        return app;
    }

    private sealed class InjectedAuditFailure : Exception { }
    private sealed class AuditFailure : SaveChangesInterceptor
    {
        internal bool Enabled { get; set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Enabled && eventData.Context!.ChangeTracker.Entries<SecurityEvent>().Any(entry =>
                entry.State == EntityState.Added && entry.Entity.EventType == "seed.client_permissions_reconciled"))
                throw new InjectedAuditFailure();
            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }
}
