using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class AdminResourceActivationTests
{
    [PostgresFact]
    public async Task ResourceActivation_PreservesSecretsCallbacksUsersOtherClientsAndLiveTokens_AndIsIdempotent()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<PandaAuthDbContext>();
        var apps = services.GetRequiredService<IOpenIddictApplicationManager>();
        var admin = await CreateAsync(apps, FirstPartyClients.AdminWeb);
        var other = await CreateAsync(apps, FirstPartyClients.MeWeb);
        db.Users.Add(new PandaUser { Id = Guid.NewGuid().ToString(), UserName = "activation-fixture", SecurityStamp = "original-stamp", PasswordHash = "original-hash" });
        db.Set<OpenIddictEntityFrameworkCoreToken>().Add(new OpenIddictEntityFrameworkCoreToken
        {
            Id = Guid.NewGuid().ToString(), Application = admin, Subject = "fixture",
            Status = Statuses.Valid, Type = TokenTypeHints.RefreshToken,
        });
        await db.SaveChangesAsync();
        var hash = admin.ClientSecret;
        var before = await db.Users.AsNoTracking().SingleAsync();
        var otherToken = other.ConcurrencyToken;
        await ApplyAsync(services);
        Assert.Equal(hash, admin.ClientSecret);
        Assert.Contains(Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope, await apps.GetPermissionsAsync(admin));
        Assert.Equal(new[] { "https://fixture.invalid/old-callback" }, (await apps.GetRedirectUrisAsync(admin)).ToArray());
        Assert.Equal(otherToken, (await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync(x => x.ClientId == FirstPartyClients.MeWeb)).ConcurrencyToken);
        var after = await db.Users.AsNoTracking().SingleAsync();
        Assert.Equal(before.PasswordHash, after.PasswordHash);
        Assert.Equal(before.SecurityStamp, after.SecurityStamp);
        Assert.Equal(Statuses.Valid, (await db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking().SingleAsync()).Status);
        Assert.Empty(await db.AdminAuditLogs.AsNoTracking().ToListAsync());
        Assert.Empty(await db.SecurityEvents.AsNoTracking().ToListAsync());
        var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
        var resource = await scopes.FindByNameAsync(PandaAuthAdminApi.Scope);
        Assert.NotNull(resource);
        Assert.Equal(new[] { PandaAuthAdminApi.Audience }, (await scopes.GetResourcesAsync(resource)).ToArray());
        var appVersion = admin.ConcurrencyToken;
        var scopeVersion = (await db.Set<OpenIddictEntityFrameworkCoreScope>().AsNoTracking().SingleAsync()).ConcurrencyToken;
        await ApplyAsync(services);
        Assert.Equal(appVersion, admin.ConcurrencyToken);
        Assert.Equal(scopeVersion, (await db.Set<OpenIddictEntityFrameworkCoreScope>().AsNoTracking().SingleAsync()).ConcurrencyToken);
    }

    [PostgresTheory]
    [InlineData("missing")]
    [InlineData("public")]
    [InlineData("foreign-grant")]
    [InlineData("wrong-audience")]
    [InlineData("missing-secret")]
    public async Task InvalidSource_RejectsBeforeAnyResourceWrites(string state)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (state != "missing")
        {
            var app = await CreateAsync(apps, FirstPartyClients.AdminWeb, state == "public");
            if (state == "missing-secret")
            {
                app.ClientSecret = null;
                await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().SaveChangesAsync();
            }
        }
        if (state == "foreign-grant")
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "fixture-foreign", ClientType = ClientTypes.Public,
                Permissions = { Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope },
            });
        }
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        if (state == "wrong-audience")
            await scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>().CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = PandaAuthAdminApi.Scope, Resources = { "fixture-foreign-audience" },
            });
        var scopeCount = await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ApplyAsync(scope.ServiceProvider));
        Assert.Equal(scopeCount, await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());
    }

    [PostgresFact]
    public async Task FailedPermissionWrite_RollsBackScopeAndPermissions()
    {
        var failure = new ApplicationFailure();
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(failure);
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await CreateAsync(apps, FirstPartyClients.AdminWeb);
            failure.Enabled = true;
            await Assert.ThrowsAsync<InjectedFailure>(() => ApplyAsync(scope.ServiceProvider));
        }
        await using var verify = fixture.Services.CreateAsyncScope();
        var db = verify.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Empty(await db.Set<OpenIddictEntityFrameworkCoreScope>().AsNoTracking().ToListAsync());
        var app = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync();
        Assert.DoesNotContain(Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope, app.Permissions ?? "");
    }

    private static async Task ApplyAsync(IServiceProvider services)
    {
        var type = typeof(DbSeeder).Assembly.GetType("PandaAuth.Server.Infrastructure.Persistence.AdminResourceActivation");
        Assert.NotNull(type);
        var method = type.GetMethod("ApplyAsync", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        await (Task)method.Invoke(null, [services])!;
    }

    private static async Task<OpenIddictEntityFrameworkCoreApplication> CreateAsync(IOpenIddictApplicationManager apps, string clientId, bool isPublic = false)
    {
        return (OpenIddictEntityFrameworkCoreApplication)await apps.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId, ClientType = isPublic ? ClientTypes.Public : ClientTypes.Confidential,
            ClientSecret = isPublic ? null : "synthetic-original-client-secret",
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code },
            RedirectUris = { new Uri("https://fixture.invalid/old-callback") },
        });
    }

    private sealed class InjectedFailure : Exception;
    private sealed class ApplicationFailure : SaveChangesInterceptor
    {
        internal bool Enabled { get; set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData data, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Enabled && data.Context!.ChangeTracker.Entries<OpenIddictEntityFrameworkCoreApplication>().Any(x => x.State == EntityState.Modified))
                throw new InjectedFailure();
            return base.SavingChangesAsync(data, result, cancellationToken);
        }
    }
}
