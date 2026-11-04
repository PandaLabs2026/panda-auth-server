using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class CloudConfigRegistrationTests
{
    [Fact]
    public async Task ExplicitRegistration_BindsFiveScopesAndOnlyConsolePermissions()
    {
        using var provider = Provider();
        await DbSeeder.SeedAsync(provider);
        await DbSeeder.SeedAsync(provider);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        var api = await applications.FindByClientIdAsync(CloudConfigScopes.IntrospectionClient);
        Assert.NotNull(api);
        Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(api));
        Assert.True(await applications.ValidateClientSecretAsync(api, "config-fixture-secret"));
        Assert.Equal(Permissions.Endpoints.Introspection, Assert.Single(await applications.GetPermissionsAsync(api)));
        var console = await applications.FindByClientIdAsync(FirstPartyClients.CloudConsoleWeb);
        Assert.NotNull(console);
        foreach (var name in CloudConfigScopes.All)
        {
            var scope = await scopes.FindByNameAsync(name);
            Assert.NotNull(scope);
            Assert.Equal(new[] { CloudConfigScopes.IntrospectionClient, CloudConfigScopes.Audience }.Order(),
                (await scopes.GetResourcesAsync(scope)).Order());
            Assert.True(await applications.HasPermissionAsync(console, Permissions.Prefixes.Scope + name));
            var unrelated = await applications.FindByClientIdAsync(FirstPartyClients.MeWeb);
            Assert.NotNull(unrelated);
            Assert.False(await applications.HasPermissionAsync(unrelated, Permissions.Prefixes.Scope + name));
        }
        Assert.False(await applications.HasPermissionAsync(console, Permissions.Endpoints.Introspection));
    }

    [Fact]
    public async Task DefaultClosed_DoesNotCreateResourceOrWidenConsole()
    {
        using var provider = Provider(enabled: false);
        await DbSeeder.SeedAsync(provider);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync(CloudConfigScopes.IntrospectionClient));
        var console = await applications.FindByClientIdAsync(FirstPartyClients.CloudConsoleWeb);
        Assert.NotNull(console);
        foreach (var name in CloudConfigScopes.All)
        {
            Assert.Null(await provider.GetRequiredService<IOpenIddictScopeManager>().FindByNameAsync(name));
            Assert.False(await applications.HasPermissionAsync(console, Permissions.Prefixes.Scope + name));
        }
    }

    [Theory]
    [InlineData("https://wrong.example/", "config-fixture-secret")]
    [InlineData("https://auth.appliket.com", "config-fixture-secret")]
    [InlineData("https://auth.appliket.com/", "")]
    public async Task InvalidRegistration_RefusesBeforeAnySeedWrites(string issuer, string secret)
    {
        using var provider = Provider(issuer: issuer, secret: secret);
        await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        Assert.Empty(db.Roles);
        Assert.Null(await provider.GetRequiredService<IOpenIddictApplicationManager>()
            .FindByClientIdAsync(FirstPartyClients.MeWeb));
    }

    [Theory]
    [InlineData("resource")]
    [InlineData("permissions")]
    [InlineData("secret")]
    public async Task ExistingRegistrationDrift_RefusesBeforeGrantingConsoleScopes(string mode)
    {
        using var provider = Provider();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        if (mode == "resource")
            await provider.GetRequiredService<IOpenIddictScopeManager>().CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = CloudConfigScopes.Read, Resources = { "unrelated-resource" },
            });
        else
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = CloudConfigScopes.IntrospectionClient, ClientType = ClientTypes.Confidential,
                ClientSecret = mode == "secret" ? "other-fixture-secret" : "config-fixture-secret",
                Permissions = { Permissions.Endpoints.Introspection },
            };
            if (mode == "permissions") descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
            await applications.CreateAsync(descriptor);
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));
        Assert.Null(await applications.FindByClientIdAsync(FirstPartyClients.CloudConsoleWeb));
    }

    [Fact]
    public async Task FleetRead_DefaultClosedDoesNotWidenFleetClient()
    {
        using var provider=Provider(fleet:true);await DbSeeder.SeedAsync(provider);
        var manager=provider.GetRequiredService<IOpenIddictApplicationManager>();
        var fleet=await manager.FindByClientIdAsync(FirstPartyClients.FleetAdminWeb);Assert.NotNull(fleet);
        foreach(var scope in CloudConfigScopes.All)Assert.False(await manager.HasPermissionAsync(fleet,Permissions.Prefixes.Scope+scope));
    }

    [Fact]
    public async Task FleetRead_ExplicitRegistrationAddsOnlyMetadataReadAndIsIdempotent()
    {
        using var provider=Provider(fleet:true,fleetRead:true);await DbSeeder.SeedAsync(provider);await DbSeeder.SeedAsync(provider);
        var manager=provider.GetRequiredService<IOpenIddictApplicationManager>();
        var fleet=await manager.FindByClientIdAsync(FirstPartyClients.FleetAdminWeb);Assert.NotNull(fleet);
        foreach(var scope in CloudConfigScopes.All)Assert.Equal(scope==CloudConfigScopes.Read,await manager.HasPermissionAsync(fleet,Permissions.Prefixes.Scope+scope));
        Assert.True(await manager.HasPermissionAsync(fleet,Permissions.Prefixes.Scope+PandaAuthScopes.FleetRead));
        Assert.Equal(ClientTypes.Confidential,await manager.GetClientTypeAsync(fleet));
        Assert.False(await manager.HasPermissionAsync(fleet,Permissions.GrantTypes.ClientCredentials));
        var unrelated=await manager.FindByClientIdAsync(FirstPartyClients.MeWeb);Assert.NotNull(unrelated);
        foreach(var scope in CloudConfigScopes.All)Assert.False(await manager.HasPermissionAsync(unrelated,Permissions.Prefixes.Scope+scope));
    }

    [Theory]
    [InlineData(false,true)] [InlineData(true,false)]
    public async Task FleetRead_MissingDependencyRefusesBeforeAnySeedWrites(bool cloud,bool fleet)
    {
        using var provider=Provider(enabled:cloud,fleet:fleet,fleetRead:true);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>DbSeeder.SeedAsync(provider));
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().Roles);
        Assert.Null(await provider.GetRequiredService<IOpenIddictApplicationManager>().FindByClientIdAsync(CloudConfigScopes.IntrospectionClient));
    }

    [Theory]
    [InlineData(CloudConfigScopes.ValuesRead)] [InlineData(CloudConfigScopes.Create)]
    [InlineData(CloudConfigScopes.Approve)] [InlineData(CloudConfigScopes.Execute)]
    public async Task FleetRead_BroaderExistingCloudPermissionRefusesWithoutRemovingIt(string scope)
    {
        using var provider=Provider(fleet:true);await DbSeeder.SeedAsync(provider);
        var manager=provider.GetRequiredService<IOpenIddictApplicationManager>();
        var fleet=await manager.FindByClientIdAsync(FirstPartyClients.FleetAdminWeb);Assert.NotNull(fleet);
        var descriptor=new OpenIddictApplicationDescriptor();await manager.PopulateAsync(descriptor,fleet);
        descriptor.Permissions.Add(Permissions.Prefixes.Scope+scope);await manager.UpdateAsync(fleet,descriptor);
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"FleetReadEnabled","true"}}).Build()
            .Bind(provider.GetRequiredService<IOptions<AuthOptions>>().Value.Seed.CloudConfig);
        var db=provider.GetRequiredService<PandaAuthDbContext>();db.Roles.RemoveRange(await db.Roles.ToListAsync());await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(()=>DbSeeder.SeedAsync(provider));Assert.Empty(db.Roles);
        Assert.True(await manager.HasPermissionAsync(fleet,Permissions.Prefixes.Scope+scope));
        Assert.False(await manager.HasPermissionAsync(fleet,Permissions.Prefixes.Scope+CloudConfigScopes.Read));
    }

    private static ServiceProvider Provider(bool enabled = true, string issuer = CloudConfigScopes.Issuer,
        string secret = "config-fixture-secret", bool fleet = false, bool fleetRead = false)
    {
        var options = new AuthOptions();
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Issuer"] = issuer,
            ["Seed:Enabled"] = "true",
            ["Seed:Admin:Password"] = "",
            ["Seed:AdminWeb:Enabled"] = "false",
            ["Seed:Me:Enabled"] = "true",
            ["Seed:Me:ClientSecret"] = "me-fixture-secret",
            ["Seed:Me:RedirectUris:0"] = "https://fixture.example/me/callback",
            ["Seed:Me:PostLogoutRedirectUris:0"] = "https://fixture.example/me/logout",
            ["Seed:CloudConsoleWeb:Enabled"] = "true",
            ["Seed:CloudConsoleWeb:ClientSecret"] = "console-fixture-secret",
            ["Seed:CloudConsoleWeb:RedirectUris:0"] = "https://fixture.example/console/callback",
            ["Seed:CloudConsoleWeb:PostLogoutRedirectUris:0"] = "https://fixture.example/console/logout",
            ["Seed:FleetAdminWeb:Enabled"] = fleet.ToString(),
            ["Seed:FleetAdminWeb:ClientSecret"] = "fleet-fixture-secret",
            ["Seed:FleetAdminWeb:RedirectUris:0"] = "https://fixture.example/fleet/callback",
            ["Seed:FleetAdminWeb:PostLogoutRedirectUris:0"] = "https://fixture.example/fleet/logout",
            ["Seed:CloudConfig:FleetReadEnabled"] = fleetRead.ToString(),
            ["Seed:CloudConfig:Enabled"] = enabled.ToString(),
            ["Seed:CloudConfig:ClientSecret"] = secret,
        }).Build().Bind(options);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(options));
        services.AddDbContext<PandaAuthDbContext>(builder => builder
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).UseOpenIddict());
        services.AddUserStore();
        services.AddOpenIddict().AddCore(builder => builder.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        return services.BuildServiceProvider();
    }
}
