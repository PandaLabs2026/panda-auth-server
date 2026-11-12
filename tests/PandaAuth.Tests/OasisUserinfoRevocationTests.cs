using System.Net;
using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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

    private sealed class ProtocolClock : TimeProvider
    {
        public TimeSpan Offset;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + Offset;
    }

}
