using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public sealed class LegacyUserColumnsDropTests
{
    private const string CutoverMigration = "RetireLegacyUserColumnMappings";

    [PostgresFact]
    public async Task Drop_removes_all_three_columns_and_preserves_canonical_data()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(migrate: false);
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var migrations = db.GetService<IMigrator>();
        await migrations.MigrateAsync(CutoverMigration);
        await SeedAsync(db);

        Assert.Equal(3, await CountLegacyColumnsAsync(db));
        await migrations.MigrateAsync();
        Assert.Equal(0, await CountLegacyColumnsAsync(db));
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        await migrations.MigrateAsync();

        db.ChangeTracker.Clear();
        Assert.Equal("login@example.test", (await db.Users.SingleAsync()).Email);
        var profile = await db.UserProfiles.SingleAsync();
        Assert.Equal("Administrator", profile.DisplayName);
        profile.DisplayName = "Edited after drop";
        await db.SaveChangesAsync();
        Assert.Equal("Edited after drop", await db.UserProfiles.Select(row => row.DisplayName).SingleAsync());
        Assert.Equal(new byte[] { 137, 80, 78, 71 }, (await db.ProfileAvatars.SingleAsync()).Bytes);
    }

    [PostgresTheory]
    [InlineData("avatar", PostgresErrorCodes.CheckViolation)]
    [InlineData("region", PostgresErrorCodes.CheckViolation)]
    [InlineData("dependent-view", PostgresErrorCodes.DependentObjectsStillExist)]
    [InlineData("locked", PostgresErrorCodes.LockNotAvailable)]
    public async Task Drop_aborts_without_changing_schema_or_history(string caseName, string sqlState)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(migrate: false);
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var migrations = db.GetService<IMigrator>();
        await migrations.MigrateAsync(CutoverMigration);
        await SeedAsync(db);
        var history = (await db.Database.GetAppliedMigrationsAsync()).ToArray();

        if (caseName == "avatar")
            await db.Database.ExecuteSqlRawAsync("""UPDATE panda_users SET "AvatarUrl" = 'legacy'""");
        if (caseName == "region")
            await db.Database.ExecuteSqlRawAsync("""UPDATE panda_users SET "Region" = ''""");
        if (caseName == "dependent-view")
            await db.Database.ExecuteSqlRawAsync("""CREATE VIEW legacy_user_view AS SELECT "Region" FROM panda_users""");

        await using var lockScope = fixture.Services.CreateAsyncScope();
        var lockDb = lockScope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        await using var blocker = caseName == "locked" ? await lockDb.Database.BeginTransactionAsync() : null;
        if (blocker is not null)
            await lockDb.Database.ExecuteSqlRawAsync("LOCK TABLE panda_users IN ACCESS SHARE MODE");

        var failure = await Record.ExceptionAsync(() => migrations.MigrateAsync());
        var error = Assert.IsType<PostgresException>(failure?.GetBaseException());
        Assert.Equal(sqlState, error.SqlState);
        if (blocker is not null) await blocker.RollbackAsync();
        Assert.Equal(3, await CountLegacyColumnsAsync(db));
        Assert.Equal(history, await db.Database.GetAppliedMigrationsAsync());
        Assert.Equal("Administrator", await db.UserProfiles.Select(row => row.DisplayName).SingleAsync());
    }

    private static async Task SeedAsync(PandaAuthDbContext db)
    {
        var user = new PandaUser { Email = "login@example.test" };
        db.Users.Add(user);
        db.UserProfiles.Add(new UserProfile { UserId = user.Id, DisplayName = "Administrator", Revision = new string('a', 32) });
        db.ProfileAvatars.Add(new ProfileAvatar { UserId = user.Id, Bytes = [137, 80, 78, 71], Width = 1, Height = 1 });
        await db.SaveChangesAsync();
    }

    private static Task<int> CountLegacyColumnsAsync(PandaAuthDbContext db)
        => db.Database.SqlQueryRaw<int>("""
            SELECT count(*)::int AS "Value"
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'panda_users'
              AND column_name IN ('Nickname', 'AvatarUrl', 'Region')
            """).SingleAsync();
}
