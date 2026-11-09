using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SelfProfilePersistenceTests
{
    [PostgresFact]
    public async Task Profile_survives_context_restart_without_rewriting_login_identity()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        var user = new PandaUser { Email = "login@example.invalid", Nickname = "login name" };
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            db.Users.Add(user);
            db.UserProfiles.Add(new UserProfile { UserId = user.Id, DisplayName = "Profile name",
                Biography = "private", Revision = new string('a', 32),
                ContactEmail = "contact@example.invalid", ContactEmailState = ProfileContactEmailState.Pending });
            db.ProfileAvatars.Add(new ProfileAvatar { UserId = user.Id, Bytes = [137, 80, 78, 71], Width = 1, Height = 1 });
            await db.SaveChangesAsync();
        }
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var profile = await db.UserProfiles.SingleAsync(p => p.UserId == user.Id);
            Assert.Equal("Profile name", profile.DisplayName);
            Assert.Equal("contact@example.invalid", profile.ContactEmail);
            Assert.Equal(ProfileContactEmailState.Pending, profile.ContactEmailState);
            Assert.Equal(new byte[] {137, 80, 78, 71}, (await db.ProfileAvatars.SingleAsync()).Bytes);
            var unchanged = await db.Users.SingleAsync(p => p.Id == user.Id);
            Assert.Equal("login@example.invalid", unchanged.Email);
            Assert.Equal("login name", unchanged.Nickname);
        }
    }

    [PostgresFact]
    public async Task Database_enforces_avatar_limit_and_account_foreign_key()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = new PandaUser();
        db.Users.Add(user);
        db.UserProfiles.Add(new UserProfile { UserId = user.Id, Revision = new string('b', 32) });
        await db.SaveChangesAsync();
        db.ProfileAvatars.Add(new ProfileAvatar { UserId = user.Id, Bytes = new byte[262145], Width = 1, Height = 1 });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        db.UserProfiles.Add(new UserProfile { UserId = "nonexistent", Revision = new string('c', 32) });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public void Profile_model_marks_revision_for_concurrency()
    {
        using var db = new DesignTimeDbContextFactory().CreateDbContext([]);
        var model = db.Model.FindEntityType(typeof(UserProfile))!;
        Assert.True(model.FindProperty(nameof(UserProfile.Revision))!.IsConcurrencyToken);
    }
    [PostgresFact]
    public async Task Stale_profile_revision_cannot_overwrite_a_committed_edit()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var firstScope = fixture.Services.CreateAsyncScope();
        await using var secondScope = fixture.Services.CreateAsyncScope();
        var first = firstScope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var second = secondScope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = new PandaUser();
        first.Users.Add(user);
        first.UserProfiles.Add(new UserProfile { UserId = user.Id, Revision = new string('a', 32) });
        await first.SaveChangesAsync();
        var stale = await second.UserProfiles.SingleAsync();
        var current = await first.UserProfiles.SingleAsync();
        current.DisplayName = "winner";
        current.Revision = new string('b', 32);
        await first.SaveChangesAsync();
        stale.DisplayName = "stale";
        stale.Revision = new string('c', 32);
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
        second.ChangeTracker.Clear();
        Assert.Equal("winner", (await second.UserProfiles.SingleAsync()).DisplayName);
    }

    [PostgresFact]
    public async Task Upgrade_preserves_existing_accounts_and_does_not_backfill_profiles()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(migrate: false);
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var migrator = db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>();
        await migrator.MigrateAsync("20261031111911_AllowTotpRotation");
        var user = new PandaUser { Email = "old@example.invalid", PasswordHash = "synthetic-credential" };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        await migrator.MigrateAsync();
        db.ChangeTracker.Clear();
        var unchanged = await db.Users.SingleAsync();
        Assert.Equal(user.Id, unchanged.Id);
        Assert.Equal("old@example.invalid", unchanged.Email);
        Assert.Equal("synthetic-credential", unchanged.PasswordHash);
        Assert.Empty(await db.UserProfiles.ToListAsync());
        Assert.Empty(await db.ProfileAvatars.ToListAsync());
        await migrator.MigrateAsync();
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
    }
}
