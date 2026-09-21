using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Messaging;
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

    [PostgresFact]
    public async Task TokenRevocation_RecordsSecurityEventWithoutTokenContent()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var db = fixture.Context();
        await db.Database.MigrateAsync();
        db.Set<OpenIddictEntityFrameworkCoreToken>().Add(new OpenIddictEntityFrameworkCoreToken
        {
            Id = "revocation-token",
            Subject = "revocation-user",
            Status = OpenIddict.Abstractions.OpenIddictConstants.Statuses.Valid,
            Type = "refresh_token",
        });
        await db.SaveChangesAsync();

        var events = new SecurityEventWriter(db, TimeProvider.System);
        await new TokenRevocationService(db, events).RevokeUserTokensAsync("revocation-user");

        db.ChangeTracker.Clear();
        Assert.Equal(OpenIddict.Abstractions.OpenIddictConstants.Statuses.Revoked,
            (await db.Set<OpenIddictEntityFrameworkCoreToken>().SingleAsync()).Status);
        var securityEvent = Assert.Single(await db.SecurityEvents.ToListAsync());
        Assert.Equal("user.tokens_revoked", securityEvent.EventType);
        Assert.Equal("revocation-user", securityEvent.UserId);
        Assert.DoesNotContain("revocation-token", securityEvent.Metadata ?? string.Empty);
    }

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

    [PostgresFact]
    public async Task ConcurrentInvalidPasswordResetAttempts_AreAtomicAndCapped()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var setup = fixture.Context();
        await setup.Database.MigrateAsync();
        var proofReadBarrier = new PasswordResetReadBarrier(AccountVerificationService.MaxAttempts + 3);
        using var provider = fixture.Services(includeAccountVerification: true, proofReadBarrier);
        var user = await CreateUserAsync(provider, "attempts@example.com");
        var proof = new PasswordResetRequest
        {
            SubjectId = user.Id,
            NormalizedTarget = "ATTEMPTS@EXAMPLE.COM",
            TokenHash = VerificationHasher.TokenHash("correct-token"),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(AccountVerificationService.TokenTtlMinutes),
        };
        setup.PasswordResetRequests.Add(proof);
        await setup.SaveChangesAsync();

        var scopes = Enumerable.Range(0, AccountVerificationService.MaxAttempts + 3)
            .Select(_ => provider.CreateAsyncScope())
            .ToArray();
        try
        {
            var results = await Task.WhenAll(scopes.Select(scope =>
                scope.ServiceProvider.GetRequiredService<AccountVerificationService>()
                    .ConsumePasswordResetAsync("attempts@example.com", "wrong-token", "NewStrong!Pass456")));

            Assert.All(results, result => Assert.False(result.Succeeded));
        }
        finally
        {
            foreach (var scope in scopes)
                await scope.DisposeAsync();
        }

        Assert.Equal(AccountVerificationService.MaxAttempts + 3, proofReadBarrier.Reads);
        await using var verify = fixture.Context();
        var stored = await verify.PasswordResetRequests.SingleAsync(request => request.Id == proof.Id);
        Assert.Equal(AccountVerificationService.MaxAttempts, stored.Attempts);
        Assert.Null(stored.ConsumedAt);
    }

    [PostgresFact]
    public async Task ConcurrentValidPasswordReset_ClaimsProofBeforeOneAccountMutation()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var setup = fixture.Context();
        await setup.Database.MigrateAsync();
        var proofReadBarrier = new PasswordResetReadBarrier(2);
        using var provider = fixture.Services(includeAccountVerification: true, proofReadBarrier);
        var user = await CreateUserAsync(provider, "consume@example.com");
        var proof = new PasswordResetRequest
        {
            SubjectId = user.Id,
            NormalizedTarget = "CONSUME@EXAMPLE.COM",
            TokenHash = VerificationHasher.TokenHash("correct-token"),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(AccountVerificationService.TokenTtlMinutes),
        };
        setup.PasswordResetRequests.Add(proof);
        await setup.SaveChangesAsync();

        var passwords = new[] { "FirstStrong!Pass456", "SecondStrong!Pass789" };
        await using var firstScope = provider.CreateAsyncScope();
        await using var secondScope = provider.CreateAsyncScope();
        var results = await Task.WhenAll(
            firstScope.ServiceProvider.GetRequiredService<AccountVerificationService>()
                .ConsumePasswordResetAsync("consume@example.com", "correct-token", passwords[0]),
            secondScope.ServiceProvider.GetRequiredService<AccountVerificationService>()
                .ConsumePasswordResetAsync("consume@example.com", "correct-token", passwords[1]));

        var winner = Assert.Single(results.Select((result, index) => (result, index)), item => item.result.Succeeded);
        var loser = Assert.Single(results, result => !result.Succeeded);
        Assert.Equal(AccountVerificationError.InvalidOrExpiredToken, loser.Error);
        Assert.Equal(2, proofReadBarrier.Reads);

        await using var verify = fixture.Context();
        var storedProof = await verify.PasswordResetRequests.SingleAsync(request => request.Id == proof.Id);
        var storedUser = await verify.Users.SingleAsync(candidate => candidate.Id == user.Id);
        Assert.NotNull(storedProof.ConsumedAt);
        Assert.Equal(PasswordVerificationOutcome.Success,
            new Argon2idPasswordHasher().Verify(storedUser.PasswordHash, passwords[winner.index]));
        Assert.Equal(PasswordVerificationOutcome.Failed,
            new Argon2idPasswordHasher().Verify(storedUser.PasswordHash, passwords[1 - winner.index]));
    }

    [PostgresFact]
    public async Task FailedEmailChangeMutation_RollsBackTokenClaim()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var setup = fixture.Context();
        await setup.Database.MigrateAsync();
        using var provider = fixture.Services(includeAccountVerification: true);
        var user = await CreateUserAsync(provider, "rollback-email@example.com");
        var token = "rollback-email-token";
        setup.EmailVerifications.Add(new EmailVerification
        {
            Purpose = AccountVerificationPurpose.EmailChange,
            SubjectId = user.Id,
            NormalizedTarget = "TAKEN-EMAIL@EXAMPLE.COM",
            TokenHash = VerificationHasher.TokenHash(token),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(AccountVerificationService.TokenTtlMinutes),
        });
        await setup.SaveChangesAsync();
        await CreateUserAsync(provider, "taken-email@example.com");

        await using var scope = provider.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();

        var rejected = await service.ConsumeEmailChangeAsync(
            user.Id, "taken-email@example.com", token);
        Assert.Equal(AccountVerificationError.DuplicateEmail, rejected.Error);

        await using (var remove = fixture.Context())
        {
            remove.Users.Remove(await remove.Users.SingleAsync(candidate => candidate.Email == "taken-email@example.com"));
            await remove.SaveChangesAsync();
        }

        var retried = await service.ConsumeEmailChangeAsync(
            user.Id, "taken-email@example.com", token);
        Assert.True(retried.Succeeded);
    }

    [PostgresFact]
    public async Task FailedPasswordResetMutation_RollsBackTokenClaim()
    {
        await using var fixture = await TestDatabase.CreateAsync();
        await using var setup = fixture.Context();
        await setup.Database.MigrateAsync();
        using var provider = fixture.Services(includeAccountVerification: true);
        var user = await CreateUserAsync(provider, "rollback-password@example.com");
        await using (var unconfirm = fixture.Context())
        {
            var storedUser = await unconfirm.Users.SingleAsync(candidate => candidate.Id == user.Id);
            storedUser.EmailConfirmed = false;
            await unconfirm.SaveChangesAsync();
        }
        var token = "rollback-password-token";
        setup.PasswordResetRequests.Add(new PasswordResetRequest
        {
            SubjectId = user.Id,
            NormalizedTarget = "ROLLBACK-PASSWORD@EXAMPLE.COM",
            TokenHash = VerificationHasher.TokenHash(token),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(AccountVerificationService.TokenTtlMinutes),
        });
        await setup.SaveChangesAsync();

        await using var firstScope = provider.CreateAsyncScope();
        var firstService = firstScope.ServiceProvider.GetRequiredService<AccountVerificationService>();

        var rejected = await firstService.ConsumePasswordResetAsync(
            user.Email!, token, "Recovered!Pass456");
        Assert.Equal(AccountVerificationError.InvalidOrExpiredToken, rejected.Error);

        await using (var confirm = fixture.Context())
        {
            var storedUser = await confirm.Users.SingleAsync(candidate => candidate.Id == user.Id);
            storedUser.EmailConfirmed = true;
            await confirm.SaveChangesAsync();
        }

        await using var secondScope = provider.CreateAsyncScope();
        var secondService = secondScope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        var retried = await secondService.ConsumePasswordResetAsync(
            user.Email!, token, "Recovered!Pass456");
        Assert.True(retried.Succeeded);
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
        public ServiceProvider Services(
            bool includeAccountVerification = false,
            DbCommandInterceptor? interceptor = null)
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDbContext<PandaAuthDbContext>(o =>
            {
                o.UseNpgsql(connectionString).UseOpenIddict();
                if (interceptor is not null)
                    o.AddInterceptors(interceptor);
            });
            services.AddUserStore();
            if (includeAccountVerification)
            {
                services.AddSingleton<IEmailSender, NullEmailSender>();
                services.AddScoped<AccountVerificationService>();
            }
            return services.BuildServiceProvider();
        }
        public async ValueTask DisposeAsync()
        {
            await using var db = Context();
            await db.Database.EnsureDeletedAsync();
        }
    }

    private sealed class NullEmailSender : IEmailSender
    {
        public Task SendVerificationCodeAsync(string email, string code, CancellationToken ct) => Task.CompletedTask;

        public Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct) => Task.CompletedTask;
    }

    private static async Task<PandaUser> CreateUserAsync(IServiceProvider provider, string email)
    {
        await using var scope = provider.CreateAsyncScope();
        var user = new PandaUser { UserName = email, Email = email, EmailConfirmed = true };
        Assert.True((await scope.ServiceProvider.GetRequiredService<UserService>()
            .CreateAsync(user, "Strong!Pass123")).Succeeded);
        return user;
    }

    private sealed class PasswordResetReadBarrier(int participants) : DbCommandInterceptor
    {
        private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int reads;
        public int Reads => Volatile.Read(ref reads);

        public override async ValueTask<DbDataReader> ReaderExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            DbDataReader result,
            CancellationToken cancellationToken = default)
        {
            if (!command.CommandText.Contains("panda_password_reset_requests", StringComparison.Ordinal) ||
                !command.CommandText.Contains("LIMIT 1", StringComparison.Ordinal))
                return await base.ReaderExecutedAsync(command, eventData, result, cancellationToken);

            if (Interlocked.Increment(ref reads) == participants)
                release.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
            return await base.ReaderExecutedAsync(command, eventData, result, cancellationToken);
        }
    }
}
