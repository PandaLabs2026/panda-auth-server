using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
using OpenIddict.Server;

namespace PandaAuth.Tests;

public sealed class OasisUserinfoRevocationTests
{
    [PostgresFact]
    public async Task Actual_oasis_tokens_are_rejected_after_current_account_or_token_invalidation()
    {
        foreach (var change in new[] { "frozen", "stamp", "revoked", "deleted" })
        {
            await using var fixture = await SecurityProtocolFixture.CreateAsync();
            await fixture.RegisterClientAsync(FirstPartyClients.OasisWeb);
            await fixture.EnableTotpAsync();
            using var browser = fixture.Browser();
            var tokens = await fixture.IssueAsync(browser, FirstPartyClients.OasisWeb, "openid offline_access");
            var access = tokens.GetProperty("access_token").GetString()!;
            async Task<HttpStatusCode> Check()
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
                using var response = await browser.SendAsync(request);
                Assert.True(response.Headers.CacheControl?.NoStore);
                return response.StatusCode;
            }
            Assert.Equal(HttpStatusCode.OK, await Check());
            if (change == "revoked")
            {
                using var scope = fixture.Host.Services.CreateScope();
                await scope.ServiceProvider.GetRequiredService<ITokenRevoker>().RevokeUserTokensAsync(fixture.UserId);
            }
            else
            {
                await using var db = fixture.Context();
                var user = await db.Users.SingleAsync(u => u.Id == fixture.UserId);
                if (change == "frozen") user.Status = UserStatus.Frozen;
                else if (change == "deleted")
                {
                    // Remove only this fixture's factor; keep the product's restrictive FK intact.
                    await db.TotpFactors.Where(factor => factor.UserId == fixture.UserId).ExecuteDeleteAsync();
                    db.Users.Remove(user);
                }
                else user.SecurityStamp = Guid.NewGuid().ToString();
                await db.SaveChangesAsync();
            }
            Assert.Equal(HttpStatusCode.Unauthorized, await Check());
        }
    }
    [PostgresFact]
    public async Task Actual_access_token_is_rejected_after_the_protocol_clock_passes_expiry()
    {
        var clock = new ProtocolClock();
        await using var fixture = await SecurityProtocolFixture.CreateAsync(configure: services =>
            services.Configure<OpenIddictServerOptions>(options => options.TimeProvider = clock));
        await fixture.RegisterClientAsync(FirstPartyClients.OasisWeb);
        await fixture.EnableTotpAsync();
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, FirstPartyClients.OasisWeb, "openid offline_access");
        async Task<HttpStatusCode> Check()
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
            using var response = await browser.SendAsync(request);
            return response.StatusCode;
        }
        Assert.Equal(HttpStatusCode.OK, await Check());
        clock.Offset = TimeSpan.FromHours(2);
        Assert.Equal(HttpStatusCode.Unauthorized, await Check());
    }

    [PostgresTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Issued_oasis_token_reads_current_display_name_with_explicit_null(bool columnsDropped)
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: new Dictionary<string, string>
        {
            ["Profile:AccountPresentationClients"] = FirstPartyClients.OasisWeb,
            ["Profile:LegacyNicknameClients"] = FirstPartyClients.OasisWeb,
        });
        if (columnsDropped)
        {
            // The cutover executable must support the physical schema of the later release.
            await using var db = fixture.Context();
            await db.Database.ExecuteSqlRawAsync("""
                ALTER TABLE panda_users DROP COLUMN "Nickname" RESTRICT,
                    DROP COLUMN "AvatarUrl" RESTRICT, DROP COLUMN "Region" RESTRICT
                """);
        }
        await fixture.RegisterClientAsync(FirstPartyClients.OasisWeb);
        await fixture.EnableTotpAsync();
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, FirstPartyClients.OasisWeb, "openid profile");
        var accessToken = tokens.GetProperty("access_token").GetString();

        async Task<string?> ReadName()
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await browser.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore);
            var identity = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(fixture.UserId, identity.GetProperty("sub").GetString());
            var displayName = identity.GetProperty(PandaAuthClaims.DisplayName).GetString();
            if (displayName is null) Assert.False(identity.TryGetProperty(PandaAuthClaims.Nickname, out _));
            else Assert.Equal(displayName, identity.GetProperty(PandaAuthClaims.Nickname).GetString());
            return displayName;
        }

        Assert.Null(await ReadName());
        await using (var db = fixture.Context())
        {
            db.UserProfiles.Add(new UserProfile
            {
                UserId = fixture.UserId,
                DisplayName = "Administrator",
                Revision = new string('a', 32),
            });
            await db.SaveChangesAsync();
        }
        Assert.Equal("Administrator", await ReadName());
    }

    private sealed class ProtocolClock : TimeProvider
    {
        public TimeSpan Offset;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + Offset;
    }

}
