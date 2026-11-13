using System.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

internal static class CloudConfigRegistration
{
    internal static async Task ApplyOnlyAsync(IServiceProvider services,AuthOptions options)
    {
        Validate(options);
        if(!options.Seed.Enabled||!options.Seed.CloudConfig.Enabled||!options.Seed.CloudConsoleWeb.Enabled||options.Seed.CloudConfig.FleetReadEnabled)
            throw new InvalidOperationException("CLOUD_CONFIG_REGISTRATION_CLOSED");
        var db=services.GetRequiredService<PandaAuthDbContext>();
        if(!db.Database.IsRelational())throw new InvalidOperationException("CLOUD_CONFIG_RELATIONAL_REQUIRED");
        await using var transaction=await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var applications=services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes=services.GetRequiredService<IOpenIddictScopeManager>();
        var console=await applications.FindByClientIdAsync(FirstPartyClients.CloudConsoleWeb)
            ??throw new InvalidOperationException("CLOUD_CONFIG_EXISTING_CONSOLE_REQUIRED");
        var permissions=await applications.GetPermissionsAsync(console);
        if(!await applications.HasClientTypeAsync(console,ClientTypes.Confidential)||
            !permissions.Contains(Permissions.GrantTypes.AuthorizationCode)||!permissions.Contains(Permissions.GrantTypes.RefreshToken))
            throw new InvalidOperationException("CLOUD_CONFIG_CONSOLE_DRIFT");
        // 已有漂移拒绝/secret不轮换语义直接复用；任一失败回滚整组登记。
        await SeedAsync(applications,scopes,options.Seed.CloudConfig);
        var added=CloudConfigScopes.All.Select(name=>Permissions.Prefixes.Scope+name).ToArray();
        if(added.Any(permission=>!permissions.Contains(permission)))
        {
            var descriptor=new OpenIddictApplicationDescriptor();await applications.PopulateAsync(descriptor,console);
            foreach(var permission in added)descriptor.Permissions.Add(permission);
            // 保留原存储hash、回调及所有其它属性，不走设置明文secret的重载。
            await applications.PopulateAsync(console,descriptor);await applications.UpdateAsync(console);
        }
        await transaction.CommitAsync();
    }

    internal static void Validate(AuthOptions options)
    {
        if (options.Seed.CloudConfig.FleetReadEnabled && (!options.Seed.CloudConfig.Enabled || !options.Seed.FleetAdminWeb.Enabled))
            throw new InvalidOperationException("CLOUD_CONFIG_FLEET_REGISTRATION_INVALID");
        if (!options.Seed.CloudConfig.Enabled) return;
        if (!string.Equals(options.Issuer, CloudConfigScopes.Issuer, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(options.Seed.CloudConfig.ClientSecret))
            throw new InvalidOperationException("CLOUD_CONFIG_REGISTRATION_INVALID");
    }

    internal static async Task ValidateFleetReadClientAsync(IOpenIddictApplicationManager applications, CloudConfigSeedOptions options)
    {
        if (!options.FleetReadEnabled) return;
        var fleet = await applications.FindByClientIdAsync(FirstPartyClients.FleetAdminWeb);
        if (fleet is null) return;
        var permissions = await applications.GetPermissionsAsync(fleet);
        if (CloudConfigScopes.All.Where(scope => scope != CloudConfigScopes.Read)
            .Any(scope => permissions.Contains(Permissions.Prefixes.Scope + scope)))
            throw new InvalidOperationException("CLOUD_CONFIG_FLEET_CLIENT_DRIFT");
    }

    internal static async Task SeedAsync(IOpenIddictApplicationManager applications,
        IOpenIddictScopeManager scopes, CloudConfigSeedOptions options)
    {
        foreach (var name in CloudConfigScopes.All)
        {
            var existing = await scopes.FindByNameAsync(name);
            if (existing is null)
                await scopes.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = name,
                    Resources = { CloudConfigScopes.Audience, CloudConfigScopes.IntrospectionClient },
                });
            else if (!(await scopes.GetResourcesAsync(existing)).ToHashSet(StringComparer.Ordinal)
                .SetEquals([CloudConfigScopes.Audience, CloudConfigScopes.IntrospectionClient]))
                throw new InvalidOperationException("CLOUD_CONFIG_SCOPE_RESOURCE_DRIFT");
        }

        var application = await applications.FindByClientIdAsync(CloudConfigScopes.IntrospectionClient);
        if (application is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = CloudConfigScopes.IntrospectionClient,
                ClientType = ClientTypes.Confidential,
                ClientSecret = options.ClientSecret,
                ConsentType = ConsentTypes.Implicit,
                Permissions = { Permissions.Endpoints.Introspection },
            });
            return;
        }
        if (!await applications.HasClientTypeAsync(application, ClientTypes.Confidential) ||
            !(await applications.GetPermissionsAsync(application)).ToHashSet(StringComparer.Ordinal)
                .SetEquals([Permissions.Endpoints.Introspection]))
            throw new InvalidOperationException("CLOUD_CONFIG_INTROSPECTION_CLIENT_DRIFT");
        // Do not silently rotate this separate resource identity during seed re-entry.
        if (!await applications.ValidateClientSecretAsync(application, options.ClientSecret))
            throw new InvalidOperationException("CLOUD_CONFIG_INTROSPECTION_SECRET_DRIFT");
    }
}
