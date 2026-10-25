using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using PandaAuth.Server.Features.Tokens;
using Xunit;

namespace PandaAuth.Tests;

public sealed class AccountSecurityVersionTests
{
    [PostgresFact]
    public async Task BulkTokenRevocation_RejectsWarmBearerWithoutChangingCookieSecurityStamp()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.RegisterClientAsync(PandaAuthAdminApi.ClientId, PandaAuthAdminApi.Scope, PandaAuthAdminApi.Audience);
        await fixture.EnableTotpAsync();
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, PandaAuthAdminApi.ClientId, "openid roles offline_access " + PandaAuthAdminApi.Scope);
        var access = tokens.GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, await SecurityProtocolFixture.ReadAdminAsync(browser, access));
        using (var scope = fixture.Host.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            var before = (await users.FindByIdAsync(fixture.UserId))!.SecurityStamp;
            await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeUserTokensAsync(fixture.UserId);
            Assert.Equal(before, (await users.FindByIdAsync(fixture.UserId))!.SecurityStamp);
        }
        Assert.Equal(HttpStatusCode.Unauthorized, await SecurityProtocolFixture.ReadAdminAsync(browser, access));
    }

    [PostgresFact]
    public async Task SecurityCommitBetweenAuthorizationAndExchange_RejectsAlreadyIssuedCode()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.RegisterClientAsync("ordinary-web");
        using var browser = fixture.Browser();
        var error = await fixture.IssueAsync(browser, "ordinary-web", beforeExchange: async () =>
        {
            using var scope = fixture.Host.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            var current = (await users.FindByIdAsync(fixture.UserId))!;
            Assert.True((await users.UpdateSecurityStampAsync(current)).Succeeded);
        }, expected: HttpStatusCode.BadRequest);
        Assert.Equal("invalid_grant", error.GetProperty("error").GetString());
    }

    [Fact]
    public async Task StaleOrMissingTicket_CannotAcquireCurrentVersion()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "version-user" };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        var source = await TestUserStoreHost.AuthenticatedPrincipalAsync(provider, user);
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        var issued = await controller.CreatePrincipalAsync(user, ["openid"], source);
        Assert.Equal(AccountSecurityVersion.From(user), issued.FindFirstValue(PandaAuthClaims.SecurityVersion));
        Assert.DoesNotContain(OpenIddictConstants.Destinations.IdentityToken,
            issued.FindFirst(PandaAuthClaims.SecurityVersion)!.GetDestinations());
        var duplicate = new ClaimsPrincipal(new ClaimsIdentity(source.Claims.Append(
            new Claim(PandaAuthClaims.SecurityVersion, AccountSecurityVersion.From(user))), "verified"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.CreatePrincipalAsync(user, ["openid"], duplicate));
        foreach (var invalid in new[] { "", new string('A', 64), new string('0', 64) })
        {
            var malformed = source.Clone().SetClaim(PandaAuthClaims.SecurityVersion, invalid);
            await Assert.ThrowsAsync<InvalidOperationException>(() => controller.CreatePrincipalAsync(user, ["openid"], malformed));
        }
        Assert.True((await users.UpdateSecurityStampAsync(user)).Succeeded);
        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.CreatePrincipalAsync(user, ["openid"], source));
        var missing = new ClaimsPrincipal(new ClaimsIdentity([new Claim(LoginSessionService.AuthenticatedAtClaim, "1700000000")], "verified"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.CreatePrincipalAsync(user, ["openid"], missing));
    }

    [PostgresFact]
    public async Task CommittedStampChange_RejectsCachedAccessAndRefreshTokens()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.RegisterClientAsync(PandaAuthAdminApi.ClientId, PandaAuthAdminApi.Scope, PandaAuthAdminApi.Audience);
        await fixture.EnableTotpAsync();
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, PandaAuthAdminApi.ClientId, "openid roles offline_access " + PandaAuthAdminApi.Scope);
        var access = tokens.GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, await SecurityProtocolFixture.ReadAdminAsync(browser, access));
        using (var scope = fixture.Host.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            var user = (await users.FindByIdAsync(fixture.UserId))!;
            Assert.True((await users.UpdateSecurityStampAsync(user)).Succeeded);
        }
        // No token-row revocation: authoritative version must defeat OpenIddict's existing positive token cache too.
        Assert.Equal(HttpStatusCode.Unauthorized, await SecurityProtocolFixture.ReadAdminAsync(browser, access));
        using var refresh = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = PandaAuthAdminApi.ClientId, ["client_secret"] = SecurityProtocolFixture.Secret,
            ["grant_type"] = "refresh_token", ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!,
        });
        using var response = await browser.PostAsync("/connect/token", refresh);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", payload.RootElement.GetProperty("error").GetString());
    }
}
