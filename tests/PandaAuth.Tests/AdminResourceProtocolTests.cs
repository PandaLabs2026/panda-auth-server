using System.Net;
using Xunit;
using PandaAuth.Shared;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace PandaAuth.Tests;

public sealed class PostgresTheoryAttribute : TheoryAttribute
{
    public PostgresTheoryAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES")))
            Skip = "Set PANDA_AUTH_TEST_POSTGRES to a disposable local PostgreSQL admin connection.";
    }
}

public sealed class AdminResourceProtocolTests
{
    [PostgresFact]
    public async Task MachineToken_EvenFromAdmittedClientAndResource_CannotAdministerHumanAccounts()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.RegisterClientAsync(PandaAuthAdminApi.ClientId, PandaAuthAdminApi.Scope, PandaAuthAdminApi.Audience);
        using (var scope = fixture.Host.Services.CreateScope())
        {
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = (await applications.FindByClientIdAsync(PandaAuthAdminApi.ClientId))!;
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, application);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            await applications.UpdateAsync(application, descriptor);
        }
        using var client = fixture.Browser();
        using var credentials = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = PandaAuthAdminApi.ClientId, ["client_secret"] = SecurityProtocolFixture.Secret,
            ["scope"] = PandaAuthAdminApi.Scope, ["grant_type"] = "client_credentials",
        });
        using var response = await client.PostAsync("/connect/token", credentials);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var payload = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Forbidden, await SecurityProtocolFixture.ReadAdminAsync(client,
            payload.RootElement.GetProperty("access_token").GetString()!));
    }

    [PostgresFact]
    public async Task OrdinaryClientAdministratorToken_CannotReadAdminApi()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.RegisterClientAsync("ordinary-web");
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, "ordinary-web");
        Assert.Equal(HttpStatusCode.Forbidden, await SecurityProtocolFixture.ReadAdminAsync(browser,
            tokens.GetProperty("access_token").GetString()!));
    }

    [PostgresTheory]
    [InlineData("admin-web", "auth.admin", "panda-auth-admin-api", true, HttpStatusCode.OK)]
    [InlineData("ordinary-web", "auth.admin", "panda-auth-admin-api", true, HttpStatusCode.Forbidden)]
    [InlineData("admin-web", "auth.admin", "other-api", true, HttpStatusCode.Forbidden)]
    [InlineData("admin-web", "other.scope", "panda-auth-admin-api", true, HttpStatusCode.Forbidden)]
    [InlineData("admin-web", "auth.admin", "panda-auth-admin-api", false, HttpStatusCode.Forbidden)]
    public async Task ResourceBoundary(string clientId, string scope, string audience, bool requestScope, HttpStatusCode expected)
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.RegisterClientAsync(clientId, scope, audience);
        // AUTH-DELIVERY-002：admin-api 主策略要求操作者已绑定 TOTP。
        await fixture.EnableTotpAsync();
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, clientId,
            "openid roles offline_access" + (requestScope ? " " + scope : ""));
        Assert.Equal(expected, await SecurityProtocolFixture.ReadAdminAsync(browser,
            tokens.GetProperty("access_token").GetString()!));
    }

    [PostgresTheory]
    [InlineData("ordinary-web", true, HttpStatusCode.Forbidden)]
    [InlineData("admin-web", false, HttpStatusCode.Forbidden)]
    [InlineData("admin-web", true, HttpStatusCode.OK)]
    public async Task RealMfaAndToken_RequireBothAdminResourceAndRoleForReadAndWrite(string clientId, bool administrator, HttpStatusCode expected)
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.RegisterClientAsync(clientId, PandaAuthAdminApi.Scope, PandaAuthAdminApi.Audience);
        await fixture.EnableTotpAsync(administrator);
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, clientId, "openid roles offline_access " + PandaAuthAdminApi.Scope);
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        Assert.Equal(expected, await SecurityProtocolFixture.ReadAdminAsync(browser, tokens.GetProperty("access_token").GetString()!));
        using var write = await browser.PostAsJsonAsync(PandaAuthAdminApi.Users,
            new AdminCreateUserRequest("resource-created", "resource-created@example.test", null, null, "Created!Password123", false));
        Assert.Equal(expected, write.StatusCode);
    }
}
