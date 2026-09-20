using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PostgresFactAttribute : FactAttribute
{
    public PostgresFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES")))
            Skip = "Set PANDA_AUTH_TEST_POSTGRES to a disposable local PostgreSQL admin connection.";
    }
}

public class UserStoreMigrationTests
{
    private const string PreviousMigration = "20260919162138_AddVerificationCodes";

    [Fact]
    public void ModelSnapshotMatchesRuntimeModel()
    {
        using var db = new DesignTimeDbContextFactory().CreateDbContext([]);
        Assert.False(db.Database.HasPendingModelChanges());
    }

    [PostgresFact]
    public async Task EmptyDatabaseCanMigrateThroughEntireHistory()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var db = fixture.Context();
        await db.Database.MigrateAsync();
        Assert.Empty(await db.Users.ToListAsync());
        Assert.Empty(await db.Roles.ToListAsync());
        Assert.Empty(await db.UserRoles.ToListAsync());
    }

    [PostgresFact]
    public async Task MfaCredentialId_IsUniqueAfterMigration()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var db = fixture.Context();
        await db.Database.MigrateAsync();

        db.Users.AddRange(
            new PandaUser { Id = "mfa-user-1", UserName = "mfa-user-1", NormalizedUserName = "MFA-USER-1" },
            new PandaUser { Id = "mfa-user-2", UserName = "mfa-user-2", NormalizedUserName = "MFA-USER-2" });
        await db.SaveChangesAsync();

        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = "mfa-user-1",
            CredentialId = [1, 2, 3],
            PublicKeyCose = [4, 5, 6],
        });
        await db.SaveChangesAsync();

        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = "mfa-user-2",
            CredentialId = [1, 2, 3],
            PublicKeyCose = [7, 8, 9],
        });

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [PostgresFact]
    public async Task MigrationPreservesAccountsMembershipsAndOpenIddictSubjects_WithoutDualWrites()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var db = fixture.Context();
        await db.GetService<IMigrator>().MigrateAsync(PreviousMigration);
        var hash = new Argon2idPasswordHasher().Hash("Legacy!Password123");
        await SeedLegacyAsync(db, hash);
        await db.Database.MigrateAsync();

        var user = await db.Users.SingleAsync();
        Assert.Equal("legacy-user", user.Id);
        Assert.Equal("LEGACY", user.NormalizedUserName);
        Assert.Equal("LEGACY@EXAMPLE.COM", user.NormalizedEmail);
        Assert.Equal(hash, user.PasswordHash);
        Assert.Equal("security-stamp", user.SecurityStamp);
        Assert.Equal("concurrency-stamp", user.ConcurrencyStamp);
        Assert.Equal(3, user.AccessFailedCount);
        Assert.True(user.LockoutEnabled);
        Assert.Equal(DateTimeOffset.Parse("2026-09-21T00:00:00Z"), user.LockoutEnd);
        Assert.True(user.EmailConfirmed);
        Assert.True(user.TwoFactorEnabled);
        Assert.Equal("legacy-role", (await db.Roles.SingleAsync()).Id);
        Assert.Equal("legacy-user", (await db.UserRoles.SingleAsync()).UserId);
        Assert.Equal("legacy-user", (await db.Set<OpenIddictEntityFrameworkCoreToken>().SingleAsync()).Subject);
        Assert.Equal("legacy-user", (await db.Set<OpenIddictEntityFrameworkCoreAuthorization>().SingleAsync()).Subject);
        Assert.True(await db.Database.SqlQueryRaw<bool>("""
            SELECT NOT EXISTS (
                SELECT "Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail",
                    "EmailConfirmed", "PasswordHash", "SecurityStamp", "ConcurrencyStamp",
                    "LockoutEnabled", "LockoutEnd", "AccessFailedCount", "Nickname", "AvatarUrl",
                    "Status", "RegisterChannel", "Region", "CreatedAt", "UpdatedAt" FROM "AspNetUsers"
                EXCEPT
                SELECT "Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail",
                    "EmailConfirmed", "PasswordHash", "SecurityStamp", "ConcurrencyStamp",
                    "LockoutEnabled", "LockoutEnd", "AccessFailedCount", "Nickname", "AvatarUrl",
                    "Status", "RegisterChannel", "Region", "CreatedAt", "UpdatedAt" FROM panda_users
            ) AS "Value"
            """).SingleAsync());
        Assert.Equal(1, await db.Database.SqlQueryRaw<int>("""SELECT count(*)::int AS "Value" FROM "AspNetUserTokens" """).SingleAsync());

        user.Nickname = "new store only";
        await db.SaveChangesAsync();
        Assert.Equal("legacy nickname", await db.Database.SqlQueryRaw<string>("""SELECT "Nickname" AS "Value" FROM "AspNetUsers" """).SingleAsync());
        // Observation tables remain readable, but accidental old binaries must fail closed.
        await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            """UPDATE "AspNetUsers" SET "Nickname" = 'must fail'"""));
    }

    [PostgresFact]
    public async Task DuplicateLegacyEmailAbortsAtomically_WithoutDeletingSource()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var db = fixture.Context();
        await db.GetService<IMigrator>().MigrateAsync(PreviousMigration);
        await SeedLegacyAsync(db, new Argon2idPasswordHasher().Hash("Legacy!Password123"));
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO "AspNetUsers" ("Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail",
                "EmailConfirmed", "PhoneNumberConfirmed", "TwoFactorEnabled", "LockoutEnabled",
                "AccessFailedCount", "Status", "RegisterChannel", "CreatedAt", "UpdatedAt")
            VALUES ('duplicate', 'duplicate', 'DUPLICATE', 'legacy@example.com', 'LEGACY@EXAMPLE.COM',
                false, false, false, true, 0, 0, 0, now(), now())
            """);
        await Assert.ThrowsAsync<PostgresException>(() => db.Database.MigrateAsync());
        Assert.Equal(2, await db.Database.SqlQueryRaw<int>("""SELECT count(*)::int AS "Value" FROM "AspNetUsers" """).SingleAsync());
        Assert.False(await db.Database.SqlQueryRaw<bool>("""SELECT to_regclass('panda_users') IS NOT NULL AS "Value" """).SingleAsync());
        // Transaction rollback must also undo the observation write guard.
        Assert.Equal(1, await db.Database.ExecuteSqlRawAsync("""UPDATE "AspNetUsers" SET "Nickname" = 'still writable' WHERE "Id" = 'duplicate'"""));
    }

    [PostgresFact]
    public async Task ConcurrentLoginFailuresAreNotLost_AndUniqueIndexesProtectDirectWrites()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var setup = fixture.Context();
        await setup.Database.MigrateAsync();
        using var provider = fixture.Services();
        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();
        var first = scope1.ServiceProvider.GetRequiredService<UserService>();
        var second = scope2.ServiceProvider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "alice", Email = "alice@example.com" };
        Assert.True((await first.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var stale = (await second.FindByIdAsync(user.Id))!;
        await Task.WhenAll(
            scope1.ServiceProvider.GetRequiredService<LoginSessionService>().CheckPasswordSignInAsync(user, "wrong", true),
            scope2.ServiceProvider.GetRequiredService<LoginSessionService>().CheckPasswordSignInAsync(stale, "wrong", true));
        Assert.Equal(2, (await setup.Users.SingleAsync()).AccessFailedCount);
        setup.Users.Add(new PandaUser { UserName = "other", NormalizedUserName = "OTHER", NormalizedEmail = "ALICE@EXAMPLE.COM" });
        await Assert.ThrowsAsync<DbUpdateException>(() => setup.SaveChangesAsync());
    }

    private static async Task SeedLegacyAsync(PandaAuthDbContext db, string hash)
    {
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO "AspNetUsers" ("Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail",
                "EmailConfirmed", "PasswordHash", "SecurityStamp", "ConcurrencyStamp", "LockoutEnabled",
                "LockoutEnd", "AccessFailedCount", "Nickname", "AvatarUrl", "Status", "RegisterChannel",
                "Region", "CreatedAt", "UpdatedAt", "PhoneNumberConfirmed", "TwoFactorEnabled")
            VALUES ('legacy-user', 'legacy', 'LEGACY', 'legacy@example.com', 'LEGACY@EXAMPLE.COM',
                true, {hash}, 'security-stamp', 'concurrency-stamp', true, '2026-09-21T00:00:00Z',
                3, 'legacy nickname', 'https://example.com/avatar', 0, 0, 'CN',
                '2026-09-01T00:00:00Z', '2026-09-02T00:00:00Z', false, true);
            INSERT INTO "AspNetRoles" ("Id", "Name", "NormalizedName", "ConcurrencyStamp")
                VALUES ('legacy-role', 'admin', 'ADMIN', 'role-stamp');
            INSERT INTO "AspNetUserRoles" ("UserId", "RoleId") VALUES ('legacy-user', 'legacy-role');
            INSERT INTO "AspNetUserTokens" ("UserId", "LoginProvider", "Name", "Value")
                VALUES ('legacy-user', 'Authenticator', 'key', 'synthetic-legacy-key');
            INSERT INTO "OpenIddictAuthorizations" ("Id", "Subject", "Status", "Type")
                VALUES ('legacy-authorization', 'legacy-user', 'valid', 'permanent');
            INSERT INTO "OpenIddictTokens" ("Id", "Subject", "Status", "Type", "AuthorizationId")
                VALUES ('legacy-token', 'legacy-user', 'valid', 'refresh_token', 'legacy-authorization');
            """);
    }

    private sealed class TestDatabase(string connectionString) : IAsyncDisposable
    {
        public static async Task<TestDatabase> CreateAsync()
        {
            var admin = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
            if (admin.Host is not ("127.0.0.1" or "localhost"))
                throw new InvalidOperationException("Migration tests require an explicitly configured local disposable PostgreSQL.");
            await using var connection = new NpgsqlConnection(admin.ConnectionString);
            await connection.OpenAsync();
            var name = "panda_store_test_" + Guid.NewGuid().ToString("N");
            await using var command = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
            await command.ExecuteNonQueryAsync();
            admin.Database = name;
            return new TestDatabase(admin.ConnectionString);
        }
        public PandaAuthDbContext Context() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(connectionString).UseOpenIddict().Options);
        public ServiceProvider Services()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<PandaAuthDbContext>(o => o.UseNpgsql(connectionString).UseOpenIddict());
            services.AddUserStore();
            return services.BuildServiceProvider();
        }
        public async ValueTask DisposeAsync()
        {
            await using var db = Context();
            await db.Database.EnsureDeletedAsync();
        }
    }
}
