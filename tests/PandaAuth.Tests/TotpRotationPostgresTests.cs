using System.Buffers.Binary;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

// PL-1031-04: exercise the migration-built PostgreSQL schema, not InMemory.
public sealed class TotpRotationPostgresTests
{
    private static readonly TestClock Clock = new();
    private static readonly TotpSecretProtector Protector = new(new byte[32], "test-v1");

    [PostgresTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Rotation_PreservesOldFactorUntilConfirmation_OnFreshAndUpgradedDatabase(bool upgrade)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        if (upgrade)
            await db.GetService<IMigrator>().MigrateAsync("20261026120000_DropWebAuthnCredentials");
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        var codes = await service.GenerateRecoveryCodesAsync(user.Id, principal, default);
        if (upgrade) await db.Database.MigrateAsync();

        var replacement = await service.BeginEnrollmentAsync(user.Id, principal, default);

        db.ChangeTracker.Clear();
        Assert.Equal(first.FactorId, (await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt != null)).Id);
        Assert.Equal(replacement.FactorId, (await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt == null)).Id);
        Assert.True(await service.VerifyAsync(user.Id, Code(first.Secret, 1), default));
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, replacement.FactorId, Code(replacement.Secret), default));
        db.ChangeTracker.Clear();
        var active = await db.TotpFactors.SingleAsync(x => x.RevokedAt == null);
        Assert.Equal(replacement.FactorId, active.Id);
        Assert.NotNull(active.ConfirmedAt);
        Assert.NotNull((await db.TotpFactors.SingleAsync(x => x.Id == first.FactorId)).RevokedAt);
        Assert.Equal(codes.Count, await db.MfaRecoveryCodes.CountAsync(x => x.ConsumedAt == null));
        Assert.True(await service.ConsumeRecoveryCodeAsync(user.Id, codes[0], default));
        Assert.False(await service.ConsumeRecoveryCodeAsync(user.Id, codes[0], default));
        Assert.True(await service.VerifyAsync(user.Id, Code(replacement.Secret, 1), default));
        Assert.False(await service.ConfirmEnrollmentAsync(user.Id, principal, replacement.FactorId, Code(replacement.Secret), default));
    }

    [PostgresFact]
    public async Task RepeatedBegin_ReplacesOnlyPendingFactor_AndInvalidCodeKeepsOldFactor()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        var abandoned = await service.BeginEnrollmentAsync(user.Id, principal, default);
        var current = await service.BeginEnrollmentAsync(user.Id, principal, default);

        Assert.False(await service.ConfirmEnrollmentAsync(user.Id, principal, abandoned.FactorId, Code(abandoned.Secret), default));
        Assert.False(await service.ConfirmEnrollmentAsync(user.Id, principal, current.FactorId, "not-a-code", default));
        db.ChangeTracker.Clear();
        Assert.Equal(first.FactorId, (await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt != null)).Id);
        Assert.Equal(current.FactorId, (await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt == null)).Id);
        Assert.NotNull((await db.TotpFactors.SingleAsync(x => x.Id == abandoned.FactorId)).RevokedAt);
    }

    [PostgresFact]
    public async Task ExpiredReplacement_DoesNotRevokeConfirmedFactor()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        var replacement = await service.BeginEnrollmentAsync(user.Id, principal, default);
        (await db.TotpFactors.SingleAsync(x => x.Id == replacement.FactorId)).CreatedAt = Clock.GetUtcNow().AddMinutes(-11);
        await db.SaveChangesAsync();

        Assert.False(await service.ConfirmEnrollmentAsync(user.Id, principal, replacement.FactorId, Code(replacement.Secret), default));
        db.ChangeTracker.Clear();
        Assert.Equal(first.FactorId, (await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt != null)).Id);
        Assert.Null((await db.TotpFactors.SingleAsync(x => x.Id == replacement.FactorId)).ConfirmedAt);
    }

    [PostgresFact]
    public async Task PromotionWriteFailure_RollsBackOldRevocation_AndAllowsRetry()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        var replacement = await service.BeginEnrollmentAsync(user.Id, principal, default);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION fail_totp_promotion() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD."ConfirmedAt" IS NULL AND NEW."ConfirmedAt" IS NOT NULL THEN
                    RAISE EXCEPTION 'injected TOTP promotion failure';
                END IF;
                RETURN NEW;
            END $$;
            CREATE TRIGGER fail_totp_promotion BEFORE UPDATE ON panda_totp_factors
            FOR EACH ROW EXECUTE FUNCTION fail_totp_promotion();
            """);

        await Assert.ThrowsAsync<DbUpdateException>(() => service.ConfirmEnrollmentAsync(
            user.Id, principal, replacement.FactorId, Code(replacement.Secret), default));

        await using (var verification = fixture.Services.CreateAsyncScope())
        {
            var stored = verification.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            Assert.Null((await stored.TotpFactors.SingleAsync(x => x.Id == first.FactorId)).RevokedAt);
            var pending = await stored.TotpFactors.SingleAsync(x => x.Id == replacement.FactorId);
            Assert.Null(pending.ConfirmedAt);
            Assert.Null(pending.LastAcceptedTimeStep);
        }
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER fail_totp_promotion ON panda_totp_factors; DROP FUNCTION fail_totp_promotion();");
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, replacement.FactorId, Code(replacement.Secret), default));
    }

    [PostgresTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentProof_IsAcceptedOnlyOnce(bool verifyConfirmed)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var pending = await service.BeginEnrollmentAsync(user.Id, principal, default);
        if (verifyConfirmed)
            Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, pending.FactorId, Code(pending.Secret), default));
        await using var blocker = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM panda_totp_factors WHERE \"Id\" = {pending.FactorId} FOR UPDATE");

        async Task<bool> Confirm()
        {
            await using var request = fixture.Services.CreateAsyncScope();
            var requestDb = request.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            return verifyConfirmed
                ? await Service(requestDb).VerifyAsync(user.Id, Code(pending.Secret, 1), default)
                : await Service(requestDb).ConfirmEnrollmentAsync(user.Id, principal, pending.FactorId, Code(pending.Secret), default);
        }
        var attempts = new[] { Confirm(), Confirm() };
        var blocked = false;
        try
        {
            blocked = await BothRequestsBlockedAsync(db);
        }
        finally { await blocker.RollbackAsync(); }
        var results = await Task.WhenAll(attempts).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(blocked, "Both confirmation requests must overlap at the database boundary.");
        Assert.Single(results, result => result);
        db.ChangeTracker.Clear();
        Assert.Single(await db.TotpFactors.Where(x => x.RevokedAt == null && x.ConfirmedAt != null).ToListAsync());
    }

    [PostgresFact]
    public async Task ConcurrentBegins_PreserveConfirmedFactorAndLeaveOnePending()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        await using var blocker = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM panda_users WHERE \"Id\" = {user.Id} FOR UPDATE");
        async Task<TotpEnrollment> Begin()
        {
            await using var request = fixture.Services.CreateAsyncScope();
            return await Service(request.ServiceProvider.GetRequiredService<PandaAuthDbContext>())
                .BeginEnrollmentAsync(user.Id, principal, default);
        }
        var attempts = new[] { Begin(), Begin() };
        var blocked = false;
        try { blocked = await BothRequestsBlockedAsync(db); }
        finally { await blocker.RollbackAsync(); }
        var results = await Task.WhenAll(attempts).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(blocked, "Both enrollment requests must overlap at the database boundary.");
        Assert.NotEqual(results[0].FactorId, results[1].FactorId);
        db.ChangeTracker.Clear();
        Assert.Equal(first.FactorId, (await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt != null)).Id);
        var pending = await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt == null);
        Assert.Contains(results, result => result.FactorId == pending.Id);
        Assert.Single(await db.TotpFactors.Where(x => x.RevokedAt != null).ToListAsync());
    }

    [PostgresFact]
    public async Task PendingInsertFailure_PreservesPreviousPendingAndConfirmedFactor()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        var pending = await service.BeginEnrollmentAsync(user.Id, principal, default);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION fail_totp_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'injected TOTP insert failure'; END $$;
            CREATE TRIGGER fail_totp_insert BEFORE INSERT ON panda_totp_factors
            FOR EACH ROW EXECUTE FUNCTION fail_totp_insert();
            """);
        await Assert.ThrowsAsync<DbUpdateException>(() => service.BeginEnrollmentAsync(user.Id, principal, default));
        await using var observer = fixture.Services.CreateAsyncScope();
        var observed = observer.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(first.FactorId, (await observed.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt != null)).Id);
        Assert.Equal(pending.FactorId, (await observed.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt == null)).Id);
        Assert.Equal(2, await observed.TotpFactors.CountAsync());
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER fail_totp_insert ON panda_totp_factors; DROP FUNCTION fail_totp_insert();");
        var retried = await service.BeginEnrollmentAsync(user.Id, principal, default);
        db.ChangeTracker.Clear();
        Assert.Equal(retried.FactorId, (await db.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt == null)).Id);
        Assert.NotNull((await db.TotpFactors.SingleAsync(x => x.Id == pending.FactorId)).RevokedAt);
    }

    [PostgresFact]
    public async Task AdminReset_WaitsForEnrollmentAndRevokesItsNewPendingFactor()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await using var db = fixture.Context();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        await using var resetScope = fixture.Host.Services.CreateAsyncScope();
        var controller = ActivatorUtilities.CreateInstance<AdminUsersController>(resetScope.ServiceProvider);
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { RequestServices = resetScope.ServiceProvider },
        };
        await TestGrants.AuthorizeAsync(resetScope.ServiceProvider, controller,
            MfaOperations.AdminResetTwoFactor, user.Id, null,
            actorId: fixture.UserId, password: fixture.AdminPassword);

        // Keep enrollment's new pending row uncommitted while reset reaches its lock wait.
        await using var enrollment = await db.Database.BeginTransactionAsync();
        var pending = await service.BeginEnrollmentAsync(user.Id, principal, default);
        var resetting = controller.ResetTwoFactor(user.Id, default);
        var blocked = false;
        try { blocked = await BothRequestsBlockedAsync(db, minimum: 1); }
        finally { await enrollment.CommitAsync(); }
        Assert.IsType<OkObjectResult>(await resetting.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.True(blocked, "Reset must overlap the uncommitted enrollment.");
        await using var observed = fixture.Context();
        Assert.Empty(await observed.TotpFactors.Where(x => x.UserId == user.Id && x.RevokedAt == null).ToListAsync());
        Assert.False(await Service(observed).ConfirmEnrollmentAsync(user.Id, principal,
            pending.FactorId, Code(pending.Secret), default));
    }

    [PostgresFact]
    public async Task Rotation_DoesNotExposeIntermediateRevocationToAnotherConnection()
    {
        var gate = new RevocationGate();
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync(gate);
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        var replacement = await service.BeginEnrollmentAsync(user.Id, principal, default);
        gate.FactorId = first.FactorId;
        var confirming = service.ConfirmEnrollmentAsync(user.Id, principal, replacement.FactorId, Code(replacement.Secret), default);
        try
        {
            await gate.Reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await using var observer = fixture.Services.CreateAsyncScope();
            var observed = observer.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            Assert.Equal(first.FactorId, (await observed.TotpFactors.SingleAsync(x => x.RevokedAt == null && x.ConfirmedAt != null)).Id);
            Assert.Null((await observed.TotpFactors.SingleAsync(x => x.Id == replacement.FactorId)).ConfirmedAt);
        }
        finally { gate.Release.TrySetResult(); }
        Assert.True(await confirming);
    }

    [PostgresTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccountFlagWriteFailure_RollsBackFactorConfirmation(bool legacy)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        user.TwoFactorEnabled = true;
        await db.SaveChangesAsync();
        var pending = await service.BeginEnrollmentAsync(user.Id, Principal(user.Id), default);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION fail_totp_account_flag() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD."TwoFactorEnabled" AND NOT NEW."TwoFactorEnabled" THEN
                    RAISE EXCEPTION 'injected account flag failure';
                END IF;
                RETURN NEW;
            END $$;
            CREATE TRIGGER fail_totp_account_flag BEFORE UPDATE ON panda_users
            FOR EACH ROW EXECUTE FUNCTION fail_totp_account_flag();
            """);
        Task<bool> Confirm() => legacy
            ? service.ConfirmLegacyReconfigurationAsync(user.Id, pending.FactorId, Code(pending.Secret), default)
            : service.ConfirmEnrollmentAsync(user.Id, Principal(user.Id), pending.FactorId, Code(pending.Secret), default);
        await Assert.ThrowsAsync<DbUpdateException>(Confirm);
        await using (var observer = fixture.Services.CreateAsyncScope())
        {
            var observed = observer.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            Assert.True((await observed.Users.SingleAsync()).TwoFactorEnabled);
            var stored = await observed.TotpFactors.SingleAsync();
            Assert.Null(stored.ConfirmedAt);
            Assert.Null(stored.LastAcceptedTimeStep);
        }
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER fail_totp_account_flag ON panda_users; DROP FUNCTION fail_totp_account_flag();");
        Assert.True(await Confirm());
        Assert.False((await db.Users.AsNoTracking().SingleAsync()).TwoFactorEnabled);
    }

    [PostgresTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Database_RejectsASecondActiveFactorInEitherSlot(bool confirmed)
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        await service.BeginEnrollmentAsync(user.Id, principal, default);
        db.TotpFactors.Add(new MfaTotpFactor
        {
            Id = Guid.NewGuid(), UserId = user.Id,
            ConfirmedAt = confirmed ? Clock.GetUtcNow() : null,
        });
        var error = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal(PostgresErrorCodes.UniqueViolation, Assert.IsType<PostgresException>(error.InnerException).SqlState);
        db.ChangeTracker.Clear();
        Assert.Equal(2, await db.TotpFactors.CountAsync(x => x.RevokedAt == null));
    }

    [PostgresFact]
    public async Task Downgrade_WithActiveRotationFailsWithoutDroppingConstraintsOrFactors()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var (user, service) = await CreateUserAsync(db);
        var principal = Principal(user.Id);
        var first = await service.BeginEnrollmentAsync(user.Id, principal, default);
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, first.FactorId, Code(first.Secret), default));
        var pending = await service.BeginEnrollmentAsync(user.Id, principal, default);
        var error = await Assert.ThrowsAsync<PostgresException>(() => db.GetService<IMigrator>()
            .MigrateAsync("20261026120000_DropWebAuthnCredentials"));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, error.SqlState);
        Assert.Contains("20261031111911_AllowTotpRotation", await db.Database.GetAppliedMigrationsAsync());
        Assert.Equal(2, await db.TotpFactors.CountAsync(x => x.RevokedAt == null));
        Assert.True(await service.ConfirmEnrollmentAsync(user.Id, principal, pending.FactorId, Code(pending.Secret), default));
    }

    private static async Task<(PandaUser User, MfaService Service)> CreateUserAsync(PandaAuthDbContext db)
    {
        var users = new UserService(db, new Argon2idPasswordHasher(), Clock);
        var user = new PandaUser { UserName = "rotation", Email = "rotation@example.test", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        return (user, Service(db));
    }

    private static MfaService Service(PandaAuthDbContext db)
    {
        var users = new UserService(db, new Argon2idPasswordHasher(), Clock);
        return new MfaService(db, users, new TotpFactorService(db, Protector, Clock),
            new LoginSessionService(users, Clock), Clock);
    }

    private static async Task<bool> BothRequestsBlockedAsync(PandaAuthDbContext db, int minimum = 2)
    {
        // Observe both lock waits; a sleep alone would not prove requests overlapped.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            await db.Database.ExecuteSqlRawAsync("SELECT pg_stat_clear_snapshot()");
            var count = await db.Database.SqlQueryRaw<int>("""
                SELECT count(*)::integer AS "Value" FROM pg_stat_activity
                WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock'
                """).SingleAsync();
            if (count >= minimum) return true;
            await Task.Delay(10);
        }
        return false;
    }

    private static ClaimsPrincipal Principal(string userId) => new(new ClaimsIdentity([
        new Claim(ClaimTypes.NameIdentifier, userId),
        new Claim(MfaClaimTypes.Method, MfaClaimTypes.Totp),
        new Claim(MfaClaimTypes.VerifiedAt, Clock.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
    ], LoginSessionService.Scheme));

    private static string Code(string base32, int offsetSteps = 0)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        var buffer = 0;
        var bits = 0;
        foreach (var character in base32)
        {
            buffer = (buffer << 5) | alphabet.IndexOf(character);
            bits += 5;
            if (bits >= 8) { bits -= 8; bytes.Add((byte)(buffer >> bits)); }
        }
        var counter = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, Clock.GetUtcNow().ToUnixTimeSeconds() / 30 + offsetSteps);
        var digest = HMACSHA1.HashData(bytes.ToArray(), counter);
        var offset = digest[^1] & 15;
        var value = (BinaryPrimitives.ReadInt32BigEndian(digest.AsSpan(offset, 4)) & int.MaxValue) % 1_000_000;
        return value.ToString("D6", CultureInfo.InvariantCulture);
    }

    private sealed class TestClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    }

    private sealed class RevocationGate : SaveChangesInterceptor
    {
        internal Guid? FactorId { get; set; }
        internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<int> SavedChangesAsync(
            SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (FactorId is not null && eventData.Context!.ChangeTracker.Entries<MfaTotpFactor>()
                .Any(entry => entry.Entity.Id == FactorId && entry.Entity.RevokedAt is not null))
            {
                FactorId = null;
                Reached.TrySetResult();
                await Release.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            }
            return result;
        }
    }
}
