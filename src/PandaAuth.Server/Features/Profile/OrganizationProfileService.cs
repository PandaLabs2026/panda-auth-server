using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile.Oasis;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

public sealed class OrganizationProfileService
{
    private readonly PandaAuthDbContext db;
    private readonly SelfProfileService profiles;
    private readonly SecurityEventWriter audit;
    private readonly ProfileOptions options;
    private readonly OasisProfileOptions oasis;
    private readonly TimeProvider clock;
    private readonly OasisProfileAccessClient membership;

    internal OrganizationProfileService(PandaAuthDbContext db, SelfProfileService profiles, SecurityEventWriter audit,
        IOptions<ProfileOptions> options, OasisProfileOptions oasis, TimeProvider clock, OasisProfileAccessClient membership)
    {
        this.db = db; this.profiles = profiles; this.audit = audit;
        this.options = options.Value; this.oasis = oasis; this.clock = clock;
        this.membership = membership;
    }

    private void Registered(Guid organizationKey)
    {
        if (!options.Enabled || !options.OrganizationsEnabled || !oasis.Enabled || !oasis.OrganizationKeys.Contains(organizationKey))
            throw new ProfileOperationException("profile_unavailable", 404);
    }

    public async Task<ProfileOrganizationSelectionDto> ReadSelectionAsync(string actorId, Guid organizationKey, CancellationToken ct)
    {
        Registered(organizationKey);
        var row = await (from user in db.Users.AsNoTracking()
            where user.Id == actorId && user.Status == UserStatus.Active
            join selection in db.ProfileOrganizationVisibilities.AsNoTracking().Where(v => v.OrganizationKey == organizationKey)
                on user.Id equals selection.UserId into selections
            from selection in selections.DefaultIfEmpty()
            select new { Selection = selection }).SingleOrDefaultAsync(ct);
        if (row is null) throw new ProfileOperationException("profile_permission_denied", 403);
        return Selection(row.Selection);
    }

    public async Task<ProfileOrganizationSelectionDto> WriteSelectionAsync(string actorId, Guid organizationKey,
        string expectedRevision, string[] validatedFields, string correlationId, CancellationToken ct)
    {
        Registered(organizationKey);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await profiles.LockActorAsync(actorId, ct);
        var previous = await db.ProfileOrganizationVisibilities.AsNoTracking()
            .SingleOrDefaultAsync(v => v.UserId == actorId && v.OrganizationKey == organizationKey, ct);
        if (Selection(previous).Revision != expectedRevision) throw new ProfileOperationException("profile_revision_mismatch", 412);
        var mask = OrganizationProfileInput.Mask(validatedFields);
        var revision = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var now = clock.GetUtcNow();
        if (previous is null)
            db.ProfileOrganizationVisibilities.Add(new ProfileOrganizationVisibility
                { UserId = actorId, OrganizationKey = organizationKey, Fields = mask, Revision = revision, UpdatedAt = now });
        else
        {
            var changed = await db.ProfileOrganizationVisibilities
                .Where(v => v.UserId == actorId && v.OrganizationKey == organizationKey && v.Revision == previous.Revision)
                .ExecuteUpdateAsync(update => update.SetProperty(v => v.Fields, mask)
                    .SetProperty(v => v.Revision, revision).SetProperty(v => v.UpdatedAt, now), ct);
            if (changed != 1) throw new ProfileOperationException("profile_revision_mismatch", 412);
        }
        await audit.RecordAsync(new SecurityEventEntry("profile.organization.visibility.updated", actorId, actorId,
            "profile.organization", organizationKey.ToString("D"), null,
            new { fields = OrganizationProfileInput.Fields((previous?.Fields ?? 0) ^ mask), revision, outcome = "success" },
            null, null, correlationId), ct);
        await transaction.CommitAsync(ct);
        return new(OrganizationProfileInput.Fields(mask), "\"" + revision + "\"");
    }

    private static ProfileOrganizationSelectionDto Selection(ProfileOrganizationVisibility? value)
        => new(OrganizationProfileInput.Fields(value?.Fields ?? 0), value is null ? "\"0\"" : "\"" + value.Revision + "\"");

    public async Task<OrganizationProfileDto> ReadMemberAsync(HttpContext caller, Guid organizationKey, Guid memberKey,
        string[] requestedFields, CancellationToken ct)
    {
        Registered(organizationKey);
        var proof = await membership.ResolveAsync(caller, organizationKey, memberKey, requestedFields, ct);
        if (proof is null) throw Unavailable();
        // One database statement observes current account, selection, profile and image availability together.
        var row = await (from user in db.Users.AsNoTracking()
            where user.Id == proof.TargetId && user.Status == UserStatus.Active
            join profile in db.UserProfiles.AsNoTracking() on user.Id equals profile.UserId into profiles
            from profile in profiles.DefaultIfEmpty()
            join visibility in db.ProfileOrganizationVisibilities.AsNoTracking().Where(v => v.OrganizationKey == organizationKey)
                on user.Id equals visibility.UserId into selections
            from visibility in selections.DefaultIfEmpty()
            select new { Profile = profile, Mask = visibility == null ? 0 : visibility.Fields,
                HasAvatar = db.ProfileAvatars.Any(a => a.UserId == user.Id) }).SingleOrDefaultAsync(ct);
        OrganizationProfileDto? result = null;
        if (row is not null)
        {
            var self = new SelfProfileDto(row.Profile?.DisplayName, row.Profile?.Biography, row.HasAvatar,
                new(row.Profile?.ContactEmail, row.Profile?.ContactEmailState ?? ProfileContactEmailState.None), "");
            result = OrganizationProfileInput.Project(self, OrganizationProfileInput.Fields(row.Mask), proof.AllowedFields, requestedFields);
        }
        await ReadAuditAsync(caller, proof.TargetId, requestedFields, result is not null, ct);
        return result ?? throw Unavailable();
    }

    public async Task<byte[]> ReadMemberAvatarAsync(HttpContext caller, Guid organizationKey, Guid memberKey, CancellationToken ct)
    {
        Registered(organizationKey);
        string[] fields = [ProfileFields.Avatar];
        var proof = await membership.ResolveAsync(caller, organizationKey, memberKey, fields, ct);
        if (proof is null) throw Unavailable();
        var mask = OrganizationProfileInput.Mask(fields);
        var row = await (from user in db.Users.AsNoTracking()
            where user.Id == proof.TargetId && user.Status == UserStatus.Active
            join visibility in db.ProfileOrganizationVisibilities.AsNoTracking() on user.Id equals visibility.UserId
            where visibility.OrganizationKey == organizationKey && (visibility.Fields & mask) != 0
            join avatar in db.ProfileAvatars.AsNoTracking() on user.Id equals avatar.UserId
            select new { avatar.Bytes }).SingleOrDefaultAsync(ct);
        await ReadAuditAsync(caller, proof.TargetId, fields, row is not null, ct);
        return row?.Bytes ?? throw Unavailable();
    }

    private Task ReadAuditAsync(HttpContext caller, string targetId, string[] fields, bool allowed, CancellationToken ct)
    {
        var actor = ProfileAccess.ActorId(caller.User);
        return audit.RecordAsync(new SecurityEventEntry("profile.organization.read", actor, actor, "profile", targetId, null,
            new { fields, outcome = allowed ? "allowed" : "unavailable" }, null, null, caller.TraceIdentifier), ct);
    }

    private static ProfileOperationException Unavailable() => new("profile_unavailable", 404);
}
