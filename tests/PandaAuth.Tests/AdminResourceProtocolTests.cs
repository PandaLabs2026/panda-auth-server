using System.Net;
using Xunit;
using PandaAuth.Shared;
using System.Net.Http.Headers;
using System.Net.Http.Json;

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
