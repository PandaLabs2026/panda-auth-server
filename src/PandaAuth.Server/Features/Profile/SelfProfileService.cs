using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

public sealed class ProfileOperationException(string code, int statusCode) : Exception(code)
{
    public string Code { get; } = code;
    public int StatusCode { get; } = statusCode;
}

/// <summary>Private profile transactions. Actor IDs come from validated delegated identity, never request DTOs.</summary>
public sealed class SelfProfileService(PandaAuthDbContext db, SecurityEventWriter audit, TimeProvider clock)
{
    public async Task<SelfProfileDto> ReadAsync(string actorId, CancellationToken ct = default)
    {
        var row = await (
            from user in db.Users.AsNoTracking()
            where user.Id == actorId && user.Status == UserStatus.Active
            join profile in db.UserProfiles.AsNoTracking() on user.Id equals profile.UserId into profiles
            from profile in profiles.DefaultIfEmpty()
            select new { Profile = profile, HasAvatar = db.ProfileAvatars.Any(a => a.UserId == user.Id) }
        ).SingleOrDefaultAsync(ct);
        if (row is null) throw Denied();
        return Projection(row.Profile, row.HasAvatar);
    }

    public async Task<SelfProfileDto> PatchAsync(string actorId, string expectedRevision,
        ProfileTextPatch patch, string correlationId, CancellationToken ct = default)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var write = await PrepareWriteAsync(actorId, expectedRevision, ct);
        var profile = write.Profile;
        if (patch.HasDisplayName) profile.DisplayName = patch.DisplayName;
        if (patch.HasBiography) profile.Biography = patch.Biography;
        await PersistWriteAsync(write, ct);
        var fields = new List<string>();
        if (patch.HasDisplayName) fields.Add("displayName");
        if (patch.HasBiography) fields.Add("biography");
        await audit.RecordAsync(new SecurityEventEntry("profile.fields.updated", actorId, actorId,
            "profile", null, null, new { fields, revision = ETag(profile), outcome = "success" },
            null, null, correlationId), ct);
        var hasAvatar = await db.ProfileAvatars.AnyAsync(a => a.UserId == actorId, ct);
        var result = Projection(profile, hasAvatar);
        await transaction.CommitAsync(ct);
        return result;
    }

    internal sealed record Write(UserProfile Profile, string? PreviousRevision);

    internal async Task LockActorAsync(string actorId, CancellationToken ct)
    {
        var actor = await db.Users.FromSqlInterpolated($"""
            SELECT * FROM panda_users WHERE "Id" = {actorId} FOR UPDATE
            """).AsNoTracking().SingleOrDefaultAsync(ct);
        if (actor?.Status != UserStatus.Active) throw Denied();
    }

    // Caller owns a transaction. All profile mutators share the immutable account lock.
    internal async Task<Write> PrepareWriteAsync(string actorId, string expectedRevision, CancellationToken ct)
    {
        await LockActorAsync(actorId, ct);
        var profile = await db.UserProfiles.AsNoTracking().SingleOrDefaultAsync(p => p.UserId == actorId, ct);
        if (!string.Equals(expectedRevision, ETag(profile), StringComparison.Ordinal)) throw Conflict();
        return new(profile ?? new UserProfile { UserId = actorId, Revision = "" }, profile?.Revision);
    }

    internal async Task PersistWriteAsync(Write write, CancellationToken ct, Guid? consumedChallenge = null)
    {
        var profile = write.Profile;
        profile.Revision = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        profile.UpdatedAt = clock.GetUtcNow();
        await db.ProfileContactChallenges.Where(c => c.UserId == profile.UserId
                && (c.State == ProfileContactChallengeState.PendingDelivery || c.State == ProfileContactChallengeState.Delivered)
                && (consumedChallenge == null || c.Id != consumedChallenge))
            .ExecuteUpdateAsync(setters => setters.SetProperty(c => c.State, ProfileContactChallengeState.Superseded), ct);
        if (write.PreviousRevision is null) db.UserProfiles.Add(profile);
        else
        {
            var changed = await db.UserProfiles.Where(p => p.UserId == profile.UserId && p.Revision == write.PreviousRevision)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(p => p.DisplayName, profile.DisplayName)
                    .SetProperty(p => p.Biography, profile.Biography)
                    .SetProperty(p => p.ContactEmail, profile.ContactEmail)
                    .SetProperty(p => p.ContactEmailState, profile.ContactEmailState)
                    .SetProperty(p => p.Revision, profile.Revision)
                    .SetProperty(p => p.UpdatedAt, profile.UpdatedAt), ct);
            if (changed != 1) throw Conflict();
        }
    }

    private static string ETag(UserProfile? profile) => profile is null ? "\"0\"" : "\"" + profile.Revision + "\"";
    private static SelfProfileDto Projection(UserProfile? profile, bool hasAvatar)
        => new(profile?.DisplayName, profile?.Biography, hasAvatar,
            new ProfileContactEmailDto(profile?.ContactEmail, profile?.ContactEmailState ?? ProfileContactEmailState.None), ETag(profile));
    private static ProfileOperationException Denied() => new("profile_permission_denied", 403);
    private static ProfileOperationException Conflict() => new("profile_revision_mismatch", 412);
}
