using System.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>Existing-instance activation: no users, credentials, callbacks or general seeding.</summary>
public static class AdminResourceActivation
{
    public static async Task ValidateSourceAsync(IServiceProvider services)
    {
        var db = services.GetRequiredService<PandaAuthDbContext>();
        var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
        var admin = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking()
            .SingleOrDefaultAsync(x => x.ClientId == FirstPartyClients.AdminWeb);
        if (admin is null || admin.ClientType != ClientTypes.Confidential || string.IsNullOrWhiteSpace(admin.ClientSecret))
            throw new InvalidOperationException("activation_admin_client_required");
        var permission = Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope;
        await foreach (var other in db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking()
                           .Where(x => x.ClientId != FirstPartyClients.AdminWeb).AsAsyncEnumerable())
        {
            if ((await applications.GetPermissionsAsync(other)).Contains(permission, StringComparer.Ordinal))
                throw new InvalidOperationException("activation_reserved_grant_conflict");
        }
        var resource = await scopes.FindByNameAsync(PandaAuthAdminApi.Scope);
        if (resource is not null && !(await scopes.GetResourcesAsync(resource)).ToHashSet(StringComparer.Ordinal)
                .SetEquals([PandaAuthAdminApi.Audience]))
            throw new InvalidOperationException("activation_admin_resource_drift");
    }

    public static async Task ApplyAsync(IServiceProvider services)
    {
        var db = services.GetRequiredService<PandaAuthDbContext>();
        if (!db.Database.IsRelational())
            throw new InvalidOperationException("activation_relational_transaction_required");
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            await ValidateSourceAsync(services);
            var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
            var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
            if (await scopes.FindByNameAsync(PandaAuthAdminApi.Scope) is null)
                await DbSeeder.SeedAdminScopeAsync(scopes);
            var application = await applications.FindByClientIdAsync(FirstPartyClients.AdminWeb)
                ?? throw new InvalidOperationException("activation_admin_client_required");
            var permission = Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope;
            if (!(await applications.GetPermissionsAsync(application)).Contains(permission, StringComparer.Ordinal))
            {
                var descriptor = new OpenIddictApplicationDescriptor();
                await applications.PopulateAsync(descriptor, application);
                descriptor.Permissions.Add(permission);
                // Populate preserves the stored hash; do not call the secret overload.
                await applications.PopulateAsync(application, descriptor);
                await applications.UpdateAsync(application);
            }
            await transaction.CommitAsync();
        }
        catch
        {
            await transaction.RollbackAsync();
            db.ChangeTracker.Clear();
            throw;
        }
    }
}
