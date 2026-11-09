using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SelfProfileServiceTests
{
    private static SelfProfileService Service(PandaAuthDbContext db)
        => new(db, new SecurityEventWriter(db, TimeProvider.System), TimeProvider.System);

    [PostgresFact]
    public async Task Empty_read_does_not_create_a_profile_or_copy_login_claims()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = new PandaUser { Nickname = "login name", Email = "login@example.invalid" };
        db.Users.Add(user); await db.SaveChangesAsync();
        var service = Service(db);
        var dto = await service.ReadAsync(user.Id);
        Assert.Null(dto.DisplayName);
        Assert.Null(dto.Biography);
        Assert.Equal("\"0\"", dto.Revision);
        Assert.False(dto.HasAvatar);
        Assert.Equal(ProfileContactEmailState.None, dto.ContactEmail.State);
        await service.ReadAsync(user.Id);
        Assert.Empty(await db.UserProfiles.ToListAsync());
    }

    [PostgresFact]
    public async Task Patch_is_atomic_with_audit_and_stale_revision_cannot_overwrite()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = new PandaUser { Nickname = "login name", Email = "login@example.invalid" };
        db.Users.Add(user); await db.SaveChangesAsync();
        var service = Service(db);
        var dto = await service.PatchAsync(user.Id, "\"0\"",
            SelfProfileInput.ParsePatch("{\"displayName\":\"Private name\",\"biography\":\"Sensitive biography\"}"), "profile-test");
        Assert.True(SelfProfileInput.IsRevision(dto.Revision));
        Assert.NotEqual("\"0\"", dto.Revision);
        var conflict = await Assert.ThrowsAsync<ProfileOperationException>(() => service.PatchAsync(user.Id, "\"0\"",
            SelfProfileInput.ParsePatch("{\"displayName\":\"stale\"}"), "profile-test"));
        Assert.Equal(412, conflict.StatusCode);
        var saved = await service.ReadAsync(user.Id);
        Assert.Equal("Private name", saved.DisplayName);
        Assert.Equal("Sensitive biography", saved.Biography);
        var audit = Assert.Single(await db.SecurityEvents.Where(e => e.EventType == "profile.fields.updated").ToListAsync());
        Assert.DoesNotContain("Private name", audit.Metadata!);
        Assert.DoesNotContain("Sensitive biography", audit.Metadata!);
        Assert.Equal("login@example.invalid", (await db.Users.SingleAsync()).Email);
        var cleared = await service.PatchAsync(user.Id, dto.Revision,
            SelfProfileInput.ParsePatch("{\"biography\":null}"), "profile-test");
        Assert.Null(cleared.Biography);
        Assert.Equal("Private name", cleared.DisplayName);
    }

    [PostgresFact]
    public async Task Concurrent_first_writes_have_one_winner_and_one_precondition_failure()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        string id;
        await using (var seed = fixture.Services.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var user = new PandaUser(); db.Users.Add(user); await db.SaveChangesAsync(); id = user.Id;
        }
        async Task<int> Write(string name)
        {
            await using var scope = fixture.Services.CreateAsyncScope();
            var service = Service(scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>());
            try
            {
                await service.PatchAsync(id, "\"0\"", SelfProfileInput.ParsePatch("{\"displayName\":\"" + name + "\"}"), "profile-race");
                return 200;
            }
            catch (ProfileOperationException e) { return e.StatusCode; }
        }
        var statuses = await Task.WhenAll(Write("first"), Write("second"));
        Assert.Equal(new[] {200, 412}, statuses.Order());
        await using var check = fixture.Services.CreateAsyncScope();
        Assert.Equal(1, await check.ServiceProvider.GetRequiredService<PandaAuthDbContext>().UserProfiles.CountAsync());
    }

    [PostgresFact]
    public async Task Frozen_accounts_cannot_read_or_write_private_profile()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = new PandaUser { Status = UserStatus.Frozen }; db.Users.Add(user); await db.SaveChangesAsync();
        var service = Service(db);
        Assert.Equal(403, (await Assert.ThrowsAsync<ProfileOperationException>(() => service.ReadAsync(user.Id))).StatusCode);
        Assert.Equal(403, (await Assert.ThrowsAsync<ProfileOperationException>(() => service.PatchAsync(user.Id, "\"0\"",
            SelfProfileInput.ParsePatch("{\"displayName\":\"rejected\"}"), "profile-test"))).StatusCode);
        Assert.Empty(await db.UserProfiles.ToListAsync());
    }
    [PostgresFact]
    public async Task Unicode_scalar_limits_roundtrip_without_utf16_parameter_truncation()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        string id;
        var name = string.Concat(Enumerable.Repeat("🐼", 80));
        var biography = string.Concat(Enumerable.Repeat("🐼", 1000));
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var user = new PandaUser(); db.Users.Add(user); await db.SaveChangesAsync(); id = user.Id;
            var patch = SelfProfileInput.ParsePatch(System.Text.Json.JsonSerializer.Serialize(new { displayName = name, biography }));
            var first = await Service(db).PatchAsync(id, "\"0\"", patch, "unicode-profile");
            await Service(db).PatchAsync(id, first.Revision, patch, "unicode-profile");
        }
        await using var check = fixture.Services.CreateAsyncScope();
        var saved = await Service(check.ServiceProvider.GetRequiredService<PandaAuthDbContext>()).ReadAsync(id);
        Assert.Equal(name, saved.DisplayName);
        Assert.Equal(biography, saved.Biography);
    }
}
