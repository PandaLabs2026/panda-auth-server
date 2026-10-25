using System.Collections.Immutable;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

internal sealed record KeyMaterial(string Id, string Use, DateTimeOffset PublishedAt,
    DateTimeOffset? StartsAt, DateTimeOffset? EndsAt, DateTimeOffset? VerifyUntil,
    RsaSecurityKey PrivateKey, RsaSecurityKey PublicKey);

internal sealed record KeyRingSnapshot(DateTimeOffset RefreshedAt, ImmutableArray<KeyMaterial> Keys);

/// <summary>One immutable snapshot per refresh; request handlers never mutate shared OpenIddict options.</summary>
internal sealed class SigningKeyRing(string connectionString, SigningKeyOptions options, TimeProvider clock)
{
    internal static readonly TimeSpan MaximumTokenLifetime = TimeSpan.FromDays(14);
    internal static readonly TimeSpan ClockMargin = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan Prepublication = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan MaximumSnapshotAge = TimeSpan.FromSeconds(120);
    private KeyRingSnapshot snapshot = new(DateTimeOffset.MinValue, []);
    private volatile bool invalidSchedule;
    internal KeyRingSnapshot Snapshot => Volatile.Read(ref snapshot);
    internal TimeProvider Clock => clock;

    internal async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        options.Validate();
        await using var lease = await DatabaseLease.AcquireAsync(connectionString, TimeSpan.FromSeconds(10), cancellationToken);
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>().UseNpgsql(connectionString).Options);
        var records = await db.SigningKeys.ToListAsync(cancellationToken);
        var now = clock.GetUtcNow();
        invalidSchedule = records.Any(key => key.Use == KeyUse.Signing &&
            (key.VerifyUntil is null || (key.SigningStartsAt is null) != (key.SigningEndsAt is null)));
        if (invalidSchedule) throw new InvalidOperationException("Incomplete signing-key metadata.");
        if (records.All(key => key.Use != KeyUse.Encryption))
            Add(KeyUse.Encryption, now, null);
        var managed = records.Where(key => key.Use == KeyUse.Signing && key.SigningStartsAt is not null)
            .OrderBy(key => key.SigningStartsAt).ToArray();
        if (managed.Length == 0)
            Add(KeyUse.Signing, now, now); // First activation only: legacy keys remain verification-only.
        else if (managed[^1].SigningStartsAt <= now)
            Add(KeyUse.Signing, now, managed[^1].SigningEndsAt > now + Prepublication
                ? managed[^1].SigningEndsAt!.Value : now + Prepublication);

        // Ensure the current signer always has a published successor, including bootstrap.
        var latest = records.Where(key => key.Use == KeyUse.Signing && key.SigningStartsAt is not null)
            .OrderByDescending(key => key.SigningStartsAt).First();
        if (latest.SigningStartsAt <= now)
            Add(KeyUse.Signing, now, latest.SigningEndsAt!.Value);

        var signing = records.Where(key => key.Use == KeyUse.Signing).ToArray();
        var scheduled = signing.Where(key => key.SigningStartsAt is not null).OrderBy(key => key.SigningStartsAt).ToArray();
        invalidSchedule = signing.Any(key => key.VerifyUntil is null ||
            (key.SigningStartsAt is not null && (key.SigningEndsAt <= key.SigningStartsAt ||
              key.NotBefore > key.SigningStartsAt ||
              key.VerifyUntil < key.SigningEndsAt + MaximumTokenLifetime + ClockMargin)))
            || scheduled.Zip(scheduled.Skip(1)).Any(pair => pair.First.SigningEndsAt > pair.Second.SigningStartsAt);
        if (invalidSchedule) throw new InvalidOperationException("Invalid signing-key schedule.");
        await db.SaveChangesAsync(cancellationToken);
        var materials = records.Where(key => key.Use == KeyUse.Encryption || key.VerifyUntil > now)
            .Select(Material).ToImmutableArray();
        Volatile.Write(ref snapshot, new(now, materials));

        void Add(string use, DateTimeOffset published, DateTimeOffset? starts)
        {
            using var rsa = RSA.Create(2048);
            var ends = starts?.AddDays(options.RotationIntervalDays);
            var until = starts?.AddDays(options.ValidityDays);
            var record = new SigningKeyRecord
            {
                KeyId = Base64UrlEncoder.Encode(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())),
                Use = use, Algorithm = use == KeyUse.Signing ? SecurityAlgorithms.RsaSha256 : "RSA-OAEP-256",
                PrivateKey = rsa.ExportPkcs8PrivateKey(), NotBefore = published,
                NotAfter = until ?? published.AddDays(options.ValidityDays),
                SigningStartsAt = starts, SigningEndsAt = ends, VerifyUntil = until,
            };
            records.Add(record);
            db.SigningKeys.Add(record);
        }
    }

    internal bool IsReady(out string reason)
    {
        var current = Snapshot;
        var now = clock.GetUtcNow();
        if (invalidSchedule) { reason = "invalid_schedule"; return false; }
        if (now < current.RefreshedAt || now - current.RefreshedAt > MaximumSnapshotAge)
        { reason = "stale_snapshot"; return false; }
        if (current.Keys.Count(key => IsSigner(key, now)) != 1)
        { reason = "no_unique_signer"; return false; }
        reason = "ready";
        return true;
    }

    internal SigningCredentials Signer()
    {
        if (!IsReady(out var reason)) throw new InvalidOperationException("Signing unavailable: " + reason);
        var now = clock.GetUtcNow();
        return new(Snapshot.Keys.Single(key => IsSigner(key, now)).PrivateKey, SecurityAlgorithms.RsaSha256);
    }

    internal IEnumerable<SecurityKey> VerificationKeys()
        => Snapshot.Keys.Where(key => key.Use == KeyUse.Signing && key.PublishedAt <= clock.GetUtcNow()
            && key.VerifyUntil > clock.GetUtcNow()).Select(key => key.PublicKey).ToArray();

    private static bool IsSigner(KeyMaterial key, DateTimeOffset now)
        => key.Use == KeyUse.Signing && key.StartsAt <= now && key.EndsAt > now;

    private static KeyMaterial Material(SigningKeyRecord record)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(record.PrivateKey, out _);
        return new(record.KeyId, record.Use, record.NotBefore, record.SigningStartsAt, record.SigningEndsAt,
            record.VerifyUntil, new(rsa.ExportParameters(true)) { KeyId = record.KeyId },
            new(rsa.ExportParameters(false)) { KeyId = record.KeyId });
    }
}
