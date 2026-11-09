using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class ProfileMeRegistrationTests
{
    [PostgresFact]
    public async Task RegisteredMeObtainsPrivateProfileAccessThroughRealAuthorizationAndRefresh()
    {
        var options = new ProfileOptions { Enabled = true, MeClientEnabled = true, AllowedClients = [FirstPartyClients.MeWeb] };
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: new Dictionary<string, string>
        {
            ["Profile:Enabled"] = "true", ["Profile:MeClientEnabled"] = "true",
            ["Profile:AllowedClients:0"] = FirstPartyClients.MeWeb,
        });
        await fixture.RegisterClientAsync(FirstPartyClients.MeWeb);
        using (var scope = fixture.Host.Services.CreateScope())
        {
            var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var app = (await apps.FindByClientIdAsync(FirstPartyClients.MeWeb))!;
            var descriptor = new OpenIddictApplicationDescriptor();
            await apps.PopulateAsync(descriptor, app);
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + Scopes.OfflineAccess);
            await apps.PopulateAsync(app, descriptor); await apps.UpdateAsync(app);
            await ProfileMeRegistration.ApplyAsync(scope.ServiceProvider, options);
        }
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, FirstPartyClients.MeWeb, "openid offline_access " + ProfileScopes.Read + " " + ProfileScopes.Write);
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        using var profile = await browser.GetAsync(PandaAuthProfileApi.Self);
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
        browser.DefaultRequestHeaders.Authorization = null;
        using var refreshed = await browser.PostAsync(PandaAuthEndpoints.Token, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token", ["client_id"] = FirstPartyClients.MeWeb,
            ["client_secret"] = SecurityProtocolFixture.Secret, ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!,
        }));
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        using var body = JsonDocument.Parse(await refreshed.Content.ReadAsStringAsync());
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.RootElement.GetProperty("access_token").GetString());
        using var reread = await browser.GetAsync(PandaAuthProfileApi.Self);
        Assert.Equal(HttpStatusCode.OK, reread.StatusCode);
    }

    [PostgresFact]
    public async Task AddsOnlyExplicitMeGrantsAndResourcesPreservingExistingIdentityAndCallbacks()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var apps = services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = FirstPartyClients.MeWeb, ClientType = ClientTypes.Confidential,
            ClientSecret = "synthetic-only-registration-secret", ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri("https://fixture.invalid/me/callback/login/pandaauth") },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken, Permissions.ResponseTypes.Code },
        };
        var client = (OpenIddictEntityFrameworkCoreApplication)await apps.CreateAsync(descriptor);
        var beforeHash = client.ClientSecret;
        var beforeCallbacks = client.RedirectUris;
        var beforePermissions = (await apps.GetPermissionsAsync(client)).ToHashSet();
        var options = new ProfileOptions { Enabled = true, MeClientEnabled = true, AllowedClients = [FirstPartyClients.MeWeb] };
        await ProfileMeRegistration.ApplyAsync(services, options);
        Assert.Equal(beforeHash, client.ClientSecret);
        Assert.Equal(beforeCallbacks, client.RedirectUris);
        Assert.Equal(beforePermissions.Append(Permissions.Prefixes.Scope + ProfileScopes.Read).Append(Permissions.Prefixes.Scope + ProfileScopes.Write).Order(), (await apps.GetPermissionsAsync(client)).Order());
        foreach (var name in new[] { ProfileScopes.Read, ProfileScopes.Write })
        {
            var resource = await scopes.FindByNameAsync(name);
            Assert.NotNull(resource);
            Assert.Equal(new[] { ProfileScopes.Resource }, (await scopes.GetResourcesAsync(resource)).ToArray());
        }
        var version = client.ConcurrencyToken;
        await ProfileMeRegistration.ApplyAsync(services, options);
        Assert.Equal(version, client.ConcurrencyToken);
    }

    [PostgresTheory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task ClosedConfigurationDoesNotCreateScopesOrClients(bool enabled, bool meEnabled)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ProfileMeRegistration.ApplyAsync(scope.ServiceProvider,
            new ProfileOptions { Enabled = enabled, MeClientEnabled = meEnabled, AllowedClients = [FirstPartyClients.MeWeb] }));
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Empty(await db.Set<OpenIddictEntityFrameworkCoreScope>().ToListAsync());
        Assert.Empty(await db.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync());
    }

    [PostgresTheory]
    [InlineData("missing-client")]
    [InlineData("public-client")]
    [InlineData("scope-drift")]
    public async Task InvalidExistingStateCannotPartiallyRegisterPrivateProfile(string mode)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var apps = services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
        if (mode != "missing-client")
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = FirstPartyClients.MeWeb,
                ClientType = mode == "public-client" ? ClientTypes.Public : ClientTypes.Confidential,
                ClientSecret = mode == "public-client" ? null : "synthetic-fixture-only",
                Permissions = { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken },
            });
        if (mode == "scope-drift")
            await scopes.CreateAsync(new OpenIddictScopeDescriptor { Name = ProfileScopes.Write, Resources = { "wrong-resource" } });
        await Assert.ThrowsAsync<InvalidOperationException>(() => ProfileMeRegistration.ApplyAsync(services,
            new ProfileOptions { Enabled = true, MeClientEnabled = true, AllowedClients = [FirstPartyClients.MeWeb] }));
        Assert.Null(await scopes.FindByNameAsync(ProfileScopes.Read));
        var client = await apps.FindByClientIdAsync(FirstPartyClients.MeWeb);
        if (client is not null)
            Assert.DoesNotContain(Permissions.Prefixes.Scope + ProfileScopes.Write, await apps.GetPermissionsAsync(client));
    }
}
