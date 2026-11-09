using PandaAuth.Server.Features.Profile;
using System.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

public static class ProfileMeRegistration
{
    public static async Task ApplyAsync(IServiceProvider services, ProfileOptions options)
    {
        if (!options.Enabled || !options.MeClientEnabled || !options.AllowedClients.Contains(FirstPartyClients.MeWeb, StringComparer.Ordinal))
            throw new InvalidOperationException("profile_me_registration_closed");
        var db = services.GetRequiredService<PandaAuthDbContext>();
        if (!db.Database.IsRelational()) throw new InvalidOperationException("profile_registration_relational_required");
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var apps = services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
        var app = await apps.FindByClientIdAsync(FirstPartyClients.MeWeb)
            ?? throw new InvalidOperationException("profile_me_existing_client_required");
        var permissions = await apps.GetPermissionsAsync(app);
        if (!await apps.HasClientTypeAsync(app, ClientTypes.Confidential)
            || !permissions.Contains(Permissions.GrantTypes.AuthorizationCode)
            || !permissions.Contains(Permissions.GrantTypes.RefreshToken))
            throw new InvalidOperationException("profile_me_client_drift");
        // Check both scope mappings before creating or changing anything.
        foreach (var name in new[] { ProfileScopes.Read, ProfileScopes.Write })
        {
            var existing = await scopes.FindByNameAsync(name);
            if (existing is not null && !(await scopes.GetResourcesAsync(existing)).ToHashSet(StringComparer.Ordinal).SetEquals([ProfileScopes.Resource]))
                throw new InvalidOperationException("profile_scope_resource_drift");
        }
        foreach (var name in new[] { ProfileScopes.Read, ProfileScopes.Write })
            if (await scopes.FindByNameAsync(name) is null)
                await scopes.CreateAsync(new OpenIddictScopeDescriptor { Name = name, Resources = { ProfileScopes.Resource } });
        if (!permissions.Contains(Permissions.Prefixes.Scope + ProfileScopes.Read) || !permissions.Contains(Permissions.Prefixes.Scope + ProfileScopes.Write))
        {
            var descriptor = new OpenIddictApplicationDescriptor();
            await apps.PopulateAsync(descriptor, app);
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + ProfileScopes.Read);
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + ProfileScopes.Write);
            // Populate carries the existing stored hash. Do not use the secret-setting overload.
            await apps.PopulateAsync(app, descriptor);
            await apps.UpdateAsync(app);
        }
        await transaction.CommitAsync();
    }
}
