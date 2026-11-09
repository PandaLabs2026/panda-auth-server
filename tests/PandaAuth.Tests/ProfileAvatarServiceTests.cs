using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ProfileAvatarServiceTests
{
    [PostgresFact]
    public async Task Avatar_roundtrips_normalized_bytes_with_revision_and_delete_is_atomic()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = new PandaUser { Email = "unchanged@example.invalid" }; db.Users.Add(user); await db.SaveChangesAsync();
        var audit = new SecurityEventWriter(db, TimeProvider.System);
        var profiles = new SelfProfileService(db, audit, TimeProvider.System);
        using var decoder = new ProfileAvatarDecoder();
        var avatars = new ProfileAvatarService(db, profiles, decoder, audit, TimeProvider.System);
        var saved = await avatars.PutAsync(user.Id, "\"0\"", ct => File.ReadAllBytesAsync(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", "seed.webp"), ct), "avatar-test");
        Assert.True(saved.HasAvatar);
        var read = await avatars.ReadAsync(user.Id);
        Assert.Equal(saved.Revision, read.Revision);
        Assert.Equal(64, read.Avatar.Width); Assert.Equal(32, read.Avatar.Height);
        Assert.True(read.Avatar.Bytes.AsSpan().StartsWith(new byte[] {137,80,78,71,13,10,26,10}));
        Assert.Equal(412, (await Assert.ThrowsAsync<ProfileOperationException>(() => avatars.DeleteAsync(user.Id, "\"0\"", "avatar-test"))).StatusCode);
        Assert.Single(await db.ProfileAvatars.ToListAsync());
        var removed = await avatars.DeleteAsync(user.Id, saved.Revision, "avatar-test");
        Assert.False(removed.HasAvatar); Assert.NotEqual(saved.Revision, removed.Revision);
        Assert.Empty(await db.ProfileAvatars.ToListAsync());
        Assert.Equal("unchanged@example.invalid", (await db.Users.SingleAsync()).Email);
    }

    [PostgresFact]
    public async Task Invalid_upload_attempts_are_persistently_rate_limited_without_creating_profile()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        string id;
        await using (var setup = fixture.Services.CreateAsyncScope())
        { var db = setup.ServiceProvider.GetRequiredService<PandaAuthDbContext>(); var user = new PandaUser(); db.Users.Add(user); await db.SaveChangesAsync(); id = user.Id; }
        using var decoder = new ProfileAvatarDecoder();
        for (var i = 0; i < 3; i++)
        {
            await using var scope = fixture.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var audit = new SecurityEventWriter(db, TimeProvider.System);
            var avatars = new ProfileAvatarService(db, new SelfProfileService(db, audit, TimeProvider.System), decoder, audit, TimeProvider.System);
            var error = await Assert.ThrowsAsync<ProfileOperationException>(() => avatars.PutAsync(id, "\"0\"", _ => Task.FromResult(new byte[] {1,2,3}), "avatar-test"));
            Assert.Equal(i == 2 ? 429 : 422, error.StatusCode);
            Assert.Empty(await db.UserProfiles.ToListAsync());
            Assert.Empty(await db.ProfileAvatars.ToListAsync());
        }
    }
    [PostgresFact]
    public async Task Restricted_runtime_role_can_write_profile_tables_but_cannot_change_schema()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = new PandaUser(); db.Users.Add(user); await db.SaveChangesAsync();
        var role = "\"ux04_runtime_" + Guid.NewGuid().ToString("N") + "\""; // Only a quoted, locally generated identifier.
        await db.Database.OpenConnectionAsync();
        async Task Sql(string sql)
        {
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }
        await Sql($"CREATE ROLE {role} NOLOGIN");
        try
        {
            await Sql($"GRANT USAGE ON SCHEMA public TO {role}");
            await Sql($"GRANT SELECT, UPDATE ON panda_users TO {role}");
            await Sql($"GRANT SELECT, INSERT, UPDATE, DELETE ON panda_user_profiles, panda_profile_avatars, panda_profile_contact_challenges, panda_profile_rate_limits, panda_security_events TO {role}");
            await Sql($"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}");
            await Sql($"SET ROLE {role}");
            var audit = new SecurityEventWriter(db, TimeProvider.System);
            var profiles = new SelfProfileService(db, audit, TimeProvider.System);
            using var decoder = new ProfileAvatarDecoder();
            var avatars = new ProfileAvatarService(db, profiles, decoder, audit, TimeProvider.System);
            var saved = await avatars.PutAsync(user.Id, "\"0\"", ct => File.ReadAllBytesAsync(
                Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", "seed.png"), ct), "runtime-role");
            Assert.True(saved.HasAvatar);
            var denied = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => Sql(
                "CREATE TABLE ux04_forbidden_schema_change (id int)"));
            Assert.Equal("42501", denied.SqlState);
        }
        finally
        {
            await Sql("RESET ROLE");
            await Sql($"DROP OWNED BY {role}");
            await Sql($"DROP ROLE {role}");
        }
    }

}
