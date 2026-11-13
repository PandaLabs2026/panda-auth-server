using System.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

internal static class CloudControlRegistration
{
    private static readonly IReadOnlyDictionary<string,string[]> Profiles = new Dictionary<string,string[]>(StringComparer.Ordinal)
    {
        [FirstPartyClients.CloudConsoleWeb]=[CloudControlScopes.ResourcesRead,CloudControlScopes.ResourcesManage,CloudControlScopes.HealthCheck,
            PandaAuthScopes.FleetServerManage,PandaAuthScopes.FleetPlatformOperate,PandaAuthScopes.FleetApprove],
        [FirstPartyClients.FleetAdminWeb]=[CloudControlScopes.HealthCheck],
        [FirstPartyClients.CloudOperationWeb]=[CloudControlScopes.SummaryRead],
    };

    internal static void Validate(AuthOptions options)
    {
        if(options.CloudControl.Enabled && options.Issuer!=CloudConfigScopes.Issuer)
            throw new InvalidOperationException("CLOUD_CONTROL_ISSUER_INVALID");
    }

    internal static async Task ApplyOnlyAsync(IServiceProvider services,AuthOptions options)
    {
        Validate(options);
        if(!options.CloudControl.Enabled)throw new InvalidOperationException("CLOUD_CONTROL_REGISTRATION_CLOSED");
        var db=services.GetRequiredService<PandaAuthDbContext>();
        if(!db.Database.IsRelational())throw new InvalidOperationException("CLOUD_CONTROL_RELATIONAL_REQUIRED");
        await using var transaction=await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var apps=services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes=services.GetRequiredService<IOpenIddictScopeManager>();
        var api=await apps.FindByClientIdAsync(FirstPartyClients.FleetApi)
            ??throw new InvalidOperationException("CLOUD_CONTROL_EXISTING_API_REQUIRED");
        if(!await apps.HasClientTypeAsync(api,ClientTypes.Confidential)||!await apps.HasPermissionAsync(api,Permissions.Endpoints.Introspection))
            throw new InvalidOperationException("CLOUD_CONTROL_API_DRIFT");
        var clients=new Dictionary<string,object>(StringComparer.Ordinal);
        var permissions=new Dictionary<string,HashSet<string>>(StringComparer.Ordinal);
        var related=CloudControlScopes.All.Concat(PandaAuthScopes.FleetAll).Select(name=>Permissions.Prefixes.Scope+name).ToHashSet(StringComparer.Ordinal);
        foreach(var (id,additions) in Profiles)
        {
            var app=await apps.FindByClientIdAsync(id)??throw new InvalidOperationException("CLOUD_CONTROL_EXISTING_WEB_REQUIRED");
            var current=(await apps.GetPermissionsAsync(app)).ToHashSet(StringComparer.Ordinal);
            var required=new[]{Permissions.Endpoints.Authorization,Permissions.Endpoints.Token,Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,Permissions.ResponseTypes.Code};
            var allowed=additions.Concat(id==FirstPartyClients.FleetAdminWeb?PandaAuthScopes.FleetAll:[])
                .Select(name=>Permissions.Prefixes.Scope+name).ToHashSet(StringComparer.Ordinal);
            if(!await apps.HasClientTypeAsync(app,ClientTypes.Confidential)||required.Any(permission=>!current.Contains(permission))
                ||!await apps.HasRequirementAsync(app,Requirements.Features.ProofKeyForCodeExchange)
                ||current.Contains(Permissions.GrantTypes.ClientCredentials)||current.Contains(Permissions.Endpoints.Introspection)
                ||current.Any(permission=>related.Contains(permission)&&!allowed.Contains(permission)))
                throw new InvalidOperationException("CLOUD_CONTROL_WEB_DRIFT");
            clients[id]=app;permissions[id]=current;
        }
        // Existing Fleet definitions are prerequisites, never recreated under another audience.
        foreach(var name in PandaAuthScopes.FleetAll)
        {
            var scope=await scopes.FindByNameAsync(name)??throw new InvalidOperationException("CLOUD_CONTROL_FLEET_SCOPE_REQUIRED");
            if(!(await scopes.GetResourcesAsync(scope)).ToHashSet(StringComparer.Ordinal).SetEquals([CloudControlScopes.Audience]))
                throw new InvalidOperationException("CLOUD_CONTROL_SCOPE_RESOURCE_DRIFT");
        }
        var missing=new List<string>();
        foreach(var name in CloudControlScopes.All)
        {
            var scope=await scopes.FindByNameAsync(name);
            if(scope is null)missing.Add(name);
            else if(!(await scopes.GetResourcesAsync(scope)).ToHashSet(StringComparer.Ordinal).SetEquals([CloudControlScopes.Audience]))
                throw new InvalidOperationException("CLOUD_CONTROL_SCOPE_RESOURCE_DRIFT");
        }
        foreach(var name in missing)
            await scopes.CreateAsync(new OpenIddictScopeDescriptor {Name=name,Resources={CloudControlScopes.Audience}});
        foreach(var (id,additions) in Profiles)
        {
            var added=additions.Select(name=>Permissions.Prefixes.Scope+name).Where(permission=>!permissions[id].Contains(permission)).ToArray();
            if(added.Length==0)continue;
            var descriptor=new OpenIddictApplicationDescriptor();await apps.PopulateAsync(descriptor,clients[id]);
            foreach(var permission in added)descriptor.Permissions.Add(permission);
            // Populate back into the existing entity; never hash a stored credential as plaintext.
            await apps.PopulateAsync(clients[id],descriptor);await apps.UpdateAsync(clients[id]);
        }
        await transaction.CommitAsync();
    }
}
