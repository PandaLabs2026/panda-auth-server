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

    private static ServiceProvider Provider(bool enabled = true, string issuer = CloudConfigScopes.Issuer,
        string secret = "config-fixture-secret")
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
