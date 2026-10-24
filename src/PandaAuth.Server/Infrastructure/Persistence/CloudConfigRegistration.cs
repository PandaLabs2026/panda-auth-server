using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

internal static class CloudConfigRegistration
{
    internal static void Validate(AuthOptions options)
    {
        if (!options.Seed.CloudConfig.Enabled) return;
        if (!string.Equals(options.Issuer, CloudConfigScopes.Issuer, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(options.Seed.CloudConfig.ClientSecret))
            throw new InvalidOperationException("CLOUD_CONFIG_REGISTRATION_INVALID");
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
