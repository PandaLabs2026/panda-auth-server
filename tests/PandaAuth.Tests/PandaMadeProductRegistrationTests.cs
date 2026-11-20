using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class PandaMadeProductRegistrationTests
{
    private const string WebSecret = "product-web-fixture-secret-at-least-32";
    private const string ApiSecret = "product-api-fixture-secret-at-least-32";

    [Fact]
    public async Task DefaultClosedDoesNotRegisterProductResources()
    {
        using var provider = CreateProvider(enabled: false);
        await DbSeeder.SeedAsync(provider);
        var apps = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        Assert.Null(await apps.FindByClientIdAsync(PandaMadeScopes.ProductWebClient));
        Assert.Null(await apps.FindByClientIdAsync(PandaMadeScopes.ProductApi));
        Assert.Null(await scopes.FindByNameAsync(PandaMadeScopes.ProductAccount));
    }

    [Fact]
    public async Task EnabledRegistrationIsIdempotentAndSeparateFromStaff()
    {
        using var provider = CreateProvider();
        await DbSeeder.SeedAsync(provider);
        await DbSeeder.SeedAsync(provider);
        var apps = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();

        var web = await apps.FindByClientIdAsync(PandaMadeScopes.ProductWebClient);
        Assert.NotNull(web);
        Assert.True(await apps.HasClientTypeAsync(web, ClientTypes.Confidential));
        Assert.True(await apps.ValidateClientSecretAsync(web, WebSecret));
        Assert.Equal("http://127.0.0.1:5091/auth/signin-oidc", Assert.Single(await apps.GetRedirectUrisAsync(web)));
        Assert.Equal("http://127.0.0.1:5091/auth/signout-callback-oidc", Assert.Single(await apps.GetPostLogoutRedirectUrisAsync(web)));
        Assert.Equal(Requirements.Features.ProofKeyForCodeExchange, Assert.Single(await apps.GetRequirementsAsync(web)));
        Assert.Contains(Permissions.GrantTypes.RefreshToken, await apps.GetPermissionsAsync(web));
        Assert.Contains(Permissions.Prefixes.Scope + PandaMadeScopes.ProductAccount, await apps.GetPermissionsAsync(web));
        Assert.DoesNotContain(Permissions.Prefixes.Scope + PandaMadeScopes.Manage, await apps.GetPermissionsAsync(web));

        var api = await apps.FindByClientIdAsync(PandaMadeScopes.ProductApi);
        Assert.NotNull(api);
        Assert.True(await apps.ValidateClientSecretAsync(api, ApiSecret));
        Assert.Equal(Permissions.Endpoints.Introspection, Assert.Single(await apps.GetPermissionsAsync(api)));
        Assert.Contains(PandaMadeScopes.ProductWebClient, FirstPartyClients.All);
        Assert.Contains(PandaMadeScopes.ProductApi, FirstPartyClients.All);

        var product = await scopes.FindByNameAsync(PandaMadeScopes.ProductAccount);
        Assert.NotNull(product);
        Assert.Equal(PandaMadeScopes.ProductApi, Assert.Single(await scopes.GetResourcesAsync(product)));
        var staff = await apps.FindByClientIdAsync(PandaMadeScopes.AdminClient);
        Assert.NotNull(staff);
        Assert.Contains(Permissions.Prefixes.Scope + PandaMadeScopes.Manage, await apps.GetPermissionsAsync(staff));
        Assert.DoesNotContain(Permissions.Prefixes.Scope + PandaMadeScopes.ProductAccount, await apps.GetPermissionsAsync(staff));
    }

    [Fact]
    public async Task ProductionCallbacksOnExistingCloudClientAreRejected()
    {
        using var provider = CreateProvider();
        await DbSeeder.SeedAsync(provider);
        var apps = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var web = await apps.FindByClientIdAsync(PandaMadeScopes.ProductWebClient);
        Assert.NotNull(web);
        var descriptor = new OpenIddictApplicationDescriptor();
        await apps.PopulateAsync(descriptor, web);
        descriptor.RedirectUris.Clear();
        descriptor.RedirectUris.Add(new Uri(PandaMadeScopes.ProductSignInCallback));
        descriptor.PostLogoutRedirectUris.Clear();
        descriptor.PostLogoutRedirectUris.Add(new Uri(PandaMadeScopes.ProductSignOutCallback));
        await apps.UpdateAsync(web, descriptor);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));
        Assert.Equal("PANDAMADE_PRODUCT_CLIENT_DRIFT", failure.Message);
        Assert.Equal(PandaMadeScopes.ProductSignInCallback, Assert.Single(await apps.GetRedirectUrisAsync(web)));
    }

    [Theory]
    [InlineData("https://auth.pandamade.net/", ApiSecret)]
    [InlineData("https://auth.pandacloud.cc/", "")]
    [InlineData("https://auth.pandacloud.cc/", WebSecret)]
    public async Task InvalidSettingsRefuseBeforeWriting(string issuer, string apiSecret)
    {
        using var provider = CreateProvider(issuer: issuer, apiSecret: apiSecret);
        await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().Roles);
    }

    [Theory]
    [InlineData("callback")]
    [InlineData("scope")]
    [InlineData("permission")]
    [InlineData("secret")]
    public async Task ExistingDriftRefusesBeforeCreatingMissingRegistration(string drift)
    {
        using var provider = CreateProvider();
        var apps = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        if (drift == "scope")
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = PandaMadeScopes.ProductAccount,
                Resources = { PandaMadeScopes.Api },
            });
        }
        else
        {
            var app = new OpenIddictApplicationDescriptor
            {
                ClientId = drift == "callback" ? PandaMadeScopes.ProductWebClient : PandaMadeScopes.ProductApi,
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Implicit,
                ClientSecret = drift == "secret" ? "other-fixture-secret" : ApiSecret,
                Permissions = { Permissions.Endpoints.Introspection },
            };
            if (drift == "callback") app.RedirectUris.Add(new Uri("https://unrelated.example/auth/callback"));
            if (drift == "permission") app.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
            await apps.CreateAsync(app);
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));
        Assert.Null(await apps.FindByClientIdAsync(drift == "callback" ? PandaMadeScopes.ProductApi : PandaMadeScopes.ProductWebClient));
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().Roles);
    }

    [PostgresFact]
    public async Task ProductRegistrationCommitsAsOneGroupAndCanRetryAfterWriteFailure()
    {
        var failure = new RejectProductApiWrite();
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(failure);
        var seed = new PandaMadeProductSeedOptions { Enabled = true, WebClientSecret = WebSecret, ApiClientSecret = ApiSecret };
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            await Assert.ThrowsAsync<InvalidOperationException>(() => PandaMadeProductRegistration.SeedAsync(
                services.GetRequiredService<PandaAuthDbContext>(),
                services.GetRequiredService<IOpenIddictApplicationManager>(),
                services.GetRequiredService<IOpenIddictScopeManager>(), seed));
            Assert.True(failure.WasHit);
        }

        failure.Enabled = false;
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            var db = services.GetRequiredService<PandaAuthDbContext>();
            Assert.Empty(await db.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync());
            Assert.Empty(await db.Set<OpenIddictEntityFrameworkCoreScope>().ToListAsync());
            await PandaMadeProductRegistration.SeedAsync(db, services.GetRequiredService<IOpenIddictApplicationManager>(),
                services.GetRequiredService<IOpenIddictScopeManager>(), seed);
        }

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            var db = services.GetRequiredService<PandaAuthDbContext>();
            await PandaMadeProductRegistration.SeedAsync(db, services.GetRequiredService<IOpenIddictApplicationManager>(),
                services.GetRequiredService<IOpenIddictScopeManager>(), seed);
            Assert.Equal(2, await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
            Assert.Equal(PandaMadeScopes.ProductAccount,
                await db.Set<OpenIddictEntityFrameworkCoreScope>().Select(value => value.Name).SingleAsync());
        }
    }

    private sealed class RejectProductApiWrite : SaveChangesInterceptor
    {
        internal bool Enabled { get; set; } = true;
        internal bool WasHit { get; private set; }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Enabled && eventData.Context!.ChangeTracker.Entries<OpenIddictEntityFrameworkCoreApplication>()
                .Any(entry => entry.State == EntityState.Added && entry.Entity.ClientId == PandaMadeScopes.ProductApi))
            {
                WasHit = true;
                throw new InvalidOperationException("simulated product API registration failure");
            }
            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }

    private static ServiceProvider CreateProvider(bool enabled = true, string issuer = PandaMadeScopes.CloudIssuer,
        string apiSecret = ApiSecret)
    {
        var options = new AuthOptions();
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Issuer"] = issuer,
            ["Seed:Enabled"] = "true",
            ["Seed:Admin:Password"] = "",
            ["Seed:AdminWeb:Enabled"] = "false",
            ["Seed:Me:Enabled"] = "false",
            ["Seed:PandamadeAdmin:Enabled"] = "true",
            ["Seed:PandamadeAdmin:ClientSecret"] = "staff-fixture-secret-at-least-32chars",
            ["Seed:PandamadeAdmin:RedirectUris:0"] = "https://admin.pandamade.net/signin-oidc",
            ["Seed:PandamadeAdmin:PostLogoutRedirectUris:0"] = "https://admin.pandamade.net/signout-callback-oidc",
            ["Seed:PandamadeProduct:Enabled"] = enabled.ToString(),
            ["Seed:PandamadeProduct:WebClientSecret"] = WebSecret,
            ["Seed:PandamadeProduct:ApiClientSecret"] = apiSecret,
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
