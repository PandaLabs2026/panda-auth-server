using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Npgsql;
using Xunit;

namespace PandaAuth.Tests;

public sealed class OnlineSigningKeyTests
{
    [PostgresFact]
    public async Task LiveSwitch_PrepublishesNewKey_AndRetainsOldTokenValidation()
    {
        var clock = new ControlledClock();
        await using var fixture = await SecurityProtocolFixture.CreateAsync(services =>
        {
            // This test drives refresh explicitly; wall-clock hosted ticks must not race its controlled clock.
            foreach (var descriptor in services.Where(item => item.ServiceType == typeof(IHostedService)
                && item.ImplementationType == typeof(SigningKeyRefreshService)).ToArray()) services.Remove(descriptor);
            services.AddSingleton(provider =>
            {
                using var scope = provider.CreateScope();
                return new SigningKeyRing(scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>()
                    .Database.GetConnectionString()!, new SigningKeyOptions(), clock);
            });
        });
        var ring = fixture.Host.Services.GetRequiredService<SigningKeyRing>();
        await using (var db = fixture.Context())
        {
            var keys = await db.SigningKeys.Where(key => key.Use == KeyUse.Signing).OrderBy(key => key.SigningStartsAt).ToArrayAsync();
            clock.Now = keys[0].SigningStartsAt!.Value;
            keys[0].SigningEndsAt = clock.Now.AddMinutes(6);
            keys[1].SigningStartsAt = keys[0].SigningEndsAt;
            await db.SaveChangesAsync();
        }
        await ring.RefreshAsync();
        var oldKid = ring.Signer().Key.KeyId;
        var publicKeys = ring.VerificationKeys().Select(key => key.KeyId).ToArray();
        Assert.Equal(2, publicKeys.Length);
        await fixture.RegisterClientAsync(PandaAuthAdminApi.ClientId, PandaAuthAdminApi.Scope, PandaAuthAdminApi.Audience);
        using var browser = fixture.Browser();
        var before = await fixture.IssueAsync(browser, PandaAuthAdminApi.ClientId, "openid roles offline_access " + PandaAuthAdminApi.Scope);
        using var jwks = JsonDocument.Parse(await browser.GetStringAsync(PandaAuthEndpoints.JsonWebKeySet));
        Assert.Equal(publicKeys.Order(), jwks.RootElement.GetProperty("keys").EnumerateArray()
            .Select(key => key.GetProperty("kid").GetString()).Order());
        Assert.All(jwks.RootElement.GetProperty("keys").EnumerateArray(), key => Assert.False(key.TryGetProperty("d", out _)));

        clock.Now = clock.Now.AddMinutes(6);
        await ring.RefreshAsync();
        Assert.NotEqual(oldKid, ring.Signer().Key.KeyId);
        Assert.Contains(ring.Signer().Key.KeyId, publicKeys);
        // The same running host now signs with the prepublished successor; original AT remains valid.
        Assert.Equal(HttpStatusCode.OK, await SecurityProtocolFixture.ReadAdminAsync(browser,
            before.GetProperty("access_token").GetString()!));
        using var newBrowser = fixture.Browser();
        var after = await fixture.IssueAsync(newBrowser, PandaAuthAdminApi.ClientId, "openid roles offline_access " + PandaAuthAdminApi.Scope);
        Assert.Equal(HttpStatusCode.OK, await SecurityProtocolFixture.ReadAdminAsync(newBrowser,
            after.GetProperty("access_token").GetString()!));
        var idToken = after.GetProperty("id_token").GetString()!;
        using var header = JsonDocument.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(idToken.Split('.')[0]));
        Assert.Equal(ring.Signer().Key.KeyId, header.RootElement.GetProperty("kid").GetString());

        clock.Now = clock.Now.AddSeconds(121);
        Assert.False(ring.IsReady(out _));
        Assert.Throws<InvalidOperationException>(() => ring.Signer());
        using var unhealthy = await browser.GetAsync("/healthz");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unhealthy.StatusCode);
        Assert.Contains(oldKid, ring.VerificationKeys().Select(key => key.KeyId));
    }

    [PostgresFact]
    public async Task ConcurrentRefreshAndRestart_KeepSingleSchedule_AndExpiredSignerIsNeverReused()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        var clock = new ControlledClock();
        var one = new SigningKeyRing(fixture.ConnectionString, new(), clock);
        var two = new SigningKeyRing(fixture.ConnectionString, new(), clock);
        await Task.WhenAll(one.RefreshAsync(), two.RefreshAsync());
        Assert.Equal(one.Signer().Key.KeyId, two.Signer().Key.KeyId);
        await using var db = fixture.Context();
        var records = await db.SigningKeys.Where(key => key.Use == KeyUse.Signing).OrderBy(key => key.SigningStartsAt).ToArrayAsync();
        Assert.Equal(2, records.Length);
        clock.Now = records[1].SigningStartsAt!.Value;
        await Task.WhenAll(one.RefreshAsync(), two.RefreshAsync());
        Assert.NotEqual(records[0].KeyId, one.Signer().Key.KeyId);
        Assert.Equal(one.Signer().Key.KeyId, two.Signer().Key.KeyId);
        Assert.Equal(3, await db.SigningKeys.CountAsync(key => key.Use == KeyUse.Signing));
        clock.Now = clock.Now.AddYears(2); // Long outage cannot turn a never-published key into an immediate signer.
        await one.RefreshAsync();
        Assert.False(one.IsReady(out _));
        Assert.Throws<InvalidOperationException>(() => one.Signer());
        clock.Now = clock.Now.AddMinutes(5);
        await one.RefreshAsync();
        Assert.True(one.IsReady(out _));
        Assert.DoesNotContain(records[0].KeyId, one.VerificationKeys().Select(key => key.KeyId));
        Assert.Equal(1, await db.SigningKeys.CountAsync(key => key.Use == KeyUse.Encryption));
    }

    private sealed class ControlledClock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [PostgresFact]
    public async Task DatabaseReadFailure_ExpiresSnapshot_AndConflictCannotReusePreviousSigner()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        var clock = new ControlledClock();
        var connection = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { CommandTimeout = 1 };
        var ring = new SigningKeyRing(connection.ConnectionString, new(), clock);
        await ring.RefreshAsync();
        var loadedAt = ring.Snapshot.RefreshedAt;
        await using (var locked = fixture.Context())
        {
            await using var transaction = await locked.Database.BeginTransactionAsync();
            await locked.Database.ExecuteSqlRawAsync("LOCK TABLE signing_keys IN ACCESS EXCLUSIVE MODE");
            await Assert.ThrowsAnyAsync<Exception>(() => ring.RefreshAsync());
            Assert.Equal(loadedAt, ring.Snapshot.RefreshedAt);
            clock.Now = clock.Now.AddSeconds(121);
            Assert.False(ring.IsReady(out _));
            Assert.NotEmpty(ring.VerificationKeys());
        }
        await ring.RefreshAsync();
        Assert.True(ring.IsReady(out _));
        await using (var conflict = fixture.Context())
        {
            var records = await conflict.SigningKeys.Where(key => key.Use == KeyUse.Signing)
                .OrderBy(key => key.SigningStartsAt).ToArrayAsync();
            records[1].SigningStartsAt = records[0].SigningStartsAt;
            await conflict.SaveChangesAsync();
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => ring.RefreshAsync());
        Assert.False(ring.IsReady(out _));
        Assert.Throws<InvalidOperationException>(() => ring.Signer());
    }
}
