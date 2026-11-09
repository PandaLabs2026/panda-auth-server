using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

public sealed class ProfileContactService(PandaAuthDbContext db, SelfProfileService profiles,
    IEmailSender email, SecurityEventWriter audit, TimeProvider clock)
{
    public async Task<ProfileContactEmailChallengeResponse> CreateAsync(string actor, string expectedRevision,
        string address, string correlation, CancellationToken ct = default)
    {
        address = SelfProfileInput.NormalizeContactAddress(address);
        var now = clock.GetUtcNow();
        var id = Guid.NewGuid(); var delivery = Guid.NewGuid();
        var bytes = RandomNumberGenerator.GetBytes(32);
        var token = WebEncoders.Base64UrlEncode(bytes);
        var digest = SHA256.HashData(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        string revision;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            var write = await profiles.PrepareWriteAsync(actor, expectedRevision, ct);
            var rate = await RateAsync(actor, ct);
            if (rate.CreationWindowStart is null || now >= rate.CreationWindowStart.Value.AddHours(1))
            { rate.CreationWindowStart = now; rate.CreationCount = 0; }
            if (rate.CreationCount >= 5 || rate.LastChallengeAt is { } last && now < last.AddSeconds(60)) throw Limited();
            rate.CreationCount++; rate.LastChallengeAt = now;
            await SaveRateAsync(rate, ct);
            write.Profile.ContactEmail = address;
            write.Profile.ContactEmailState = ProfileContactEmailState.Pending;
            await profiles.PersistWriteAsync(write, ct);
            revision = write.Profile.Revision;
            db.ProfileContactChallenges.Add(new ProfileContactChallenge
            {
                Id = id, DeliveryId = delivery, UserId = actor, Address = address, TokenDigest = digest,
                ExpectedRevision = revision, CreatedAt = now, ExpiresAt = now.AddMinutes(10),
            });
            await RecordAsync("profile.contact.challenge.created", actor, id, correlation, "pending", ct);
            await transaction.CommitAsync(ct);
        }
        // The token is only in this send call's memory. No database lock is held during transport.
        try { await email.SendProfileContactVerificationAsync(address, token, delivery, ct); }
        catch (Exception error) when (error is HttpRequestException or OperationCanceledException or InvalidOperationException or NotSupportedException)
        { throw new ProfileOperationException("contact_delivery_unconfirmed", 503); }
        SelfProfileDto acceptedProfile;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            await profiles.LockActorAsync(actor, ct);
            var current = await db.UserProfiles.AsNoTracking().SingleAsync(p => p.UserId == actor, ct);
            if (current.Revision != revision) throw new ProfileOperationException("profile_revision_mismatch", 412);
            var accepted = await db.ProfileContactChallenges.Where(c => c.Id == id && c.UserId == actor
                    && c.ExpectedRevision == revision && c.State == ProfileContactChallengeState.PendingDelivery && c.ExpiresAt > clock.GetUtcNow())
                .ExecuteUpdateAsync(setters => setters.SetProperty(c => c.State, ProfileContactChallengeState.Delivered), ct);
            if (accepted != 1) throw new ProfileOperationException("profile_revision_mismatch", 412);
            acceptedProfile = await profiles.ReadAsync(actor, ct);
            await transaction.CommitAsync(ct);
        }
        return new(acceptedProfile, id.ToString("D"));
    }

    public async Task<SelfProfileDto> ConfirmAsync(string actor, string challengeId, string token,
        string correlation, CancellationToken ct = default)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await profiles.LockActorAsync(actor, ct);
        var rate = await RateAsync(actor, ct); var now = clock.GetUtcNow();
        if (rate.ConfirmationWindowStart is null || now >= rate.ConfirmationWindowStart.Value.AddMinutes(1))
        { rate.ConfirmationWindowStart = now; rate.ConfirmationCount = 0; }
        if (rate.ConfirmationCount >= 10) throw Limited();
        rate.ConfirmationCount++;
        await SaveRateAsync(rate, ct);
        async Task Reject(int status = 422, Guid? owned = null)
        {
            await RecordAsync("profile.contact.challenge.rejected", actor, owned, correlation, "invalid", ct);
            await transaction.CommitAsync(ct);
            throw new ProfileOperationException(status == 400 ? "profile_request_invalid" : "contact_challenge_invalid", status);
        }
        if (!Guid.TryParseExact(challengeId, "D", out var id) || id.ToString("D") != challengeId || !CanonicalToken(token))
            await Reject(400);
        var challenge = await db.ProfileContactChallenges.AsNoTracking().SingleOrDefaultAsync(c => c.Id == id && c.UserId == actor, ct);
        var profile = await db.UserProfiles.AsNoTracking().SingleOrDefaultAsync(p => p.UserId == actor, ct);
        if (challenge is null || profile is null) await Reject();
        if (challenge!.State != ProfileContactChallengeState.Delivered || challenge.FailedAttempts >= 5
            || profile!.Revision != challenge.ExpectedRevision || profile.ContactEmailState != ProfileContactEmailState.Pending
            || !string.Equals(profile.ContactEmail, challenge.Address, StringComparison.Ordinal)) await Reject(owned: challenge.Id);
        if (challenge.ExpiresAt <= now)
        {
            await db.ProfileContactChallenges.Where(c => c.Id == id).ExecuteUpdateAsync(s => s.SetProperty(c => c.State, ProfileContactChallengeState.Expired), ct);
            await Reject(owned: id);
        }
        var raw = WebEncoders.Base64UrlDecode(token);
        var matches = CryptographicOperations.FixedTimeEquals(SHA256.HashData(raw), challenge.TokenDigest);
        CryptographicOperations.ZeroMemory(raw);
        if (!matches)
        {
            var failed = challenge.FailedAttempts + 1;
            await db.ProfileContactChallenges.Where(c => c.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(c => c.FailedAttempts, failed)
                .SetProperty(c => c.State, failed >= 5 ? ProfileContactChallengeState.Failed : ProfileContactChallengeState.Delivered), ct);
            await Reject(owned: id);
        }
        var consumed = await db.ProfileContactChallenges.Where(c => c.Id == id && c.UserId == actor
                && c.State == ProfileContactChallengeState.Delivered && c.ExpiresAt > clock.GetUtcNow())
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.State, ProfileContactChallengeState.Consumed), ct);
        if (consumed != 1) await Reject(owned: id);
        profile!.ContactEmailState = ProfileContactEmailState.Verified;
        await profiles.PersistWriteAsync(new SelfProfileService.Write(profile, profile.Revision), ct, consumedChallenge: id);
        await RecordAsync("profile.contact.challenge.confirmed", actor, id, correlation, "verified", ct);
        var result = await profiles.ReadAsync(actor, ct);
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<SelfProfileDto> DeleteAsync(string actor, string expectedRevision,
        string correlation, CancellationToken ct = default)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var write = await profiles.PrepareWriteAsync(actor, expectedRevision, ct);
        write.Profile.ContactEmail = null;
        write.Profile.ContactEmailState = ProfileContactEmailState.None;
        await profiles.PersistWriteAsync(write, ct);
        await db.ProfileContactChallenges.Where(c => c.UserId == actor).ExecuteDeleteAsync(ct);
        await RecordAsync("profile.contact.deleted", actor, null, correlation, "removed", ct);
        var result = await profiles.ReadAsync(actor, ct);
        await transaction.CommitAsync(ct);
        return result;
    }

    private async Task<ProfileRateLimit> RateAsync(string actor, CancellationToken ct)
        => await db.ProfileRateLimits.AsNoTracking().SingleOrDefaultAsync(r => r.UserId == actor, ct) ?? new ProfileRateLimit { UserId = actor };
    private async Task SaveRateAsync(ProfileRateLimit rate, CancellationToken ct)
    {
        var changed = await db.ProfileRateLimits.Where(r => r.UserId == rate.UserId).ExecuteUpdateAsync(s => s
            .SetProperty(r => r.CreationWindowStart, rate.CreationWindowStart)
            .SetProperty(r => r.CreationCount, rate.CreationCount)
            .SetProperty(r => r.LastChallengeAt, rate.LastChallengeAt)
            .SetProperty(r => r.ConfirmationWindowStart, rate.ConfirmationWindowStart)
            .SetProperty(r => r.ConfirmationCount, rate.ConfirmationCount), ct);
        if (changed == 0) db.ProfileRateLimits.Add(rate);
    }
    private Task RecordAsync(string kind, string actor, Guid? challenge, string correlation, string outcome, CancellationToken ct)
        => audit.RecordAsync(new SecurityEventEntry(kind, actor, actor, "profile-contact-challenge", challenge?.ToString("D"), null,
            new { fields = new[] { "contactEmail" }, outcome }, null, null, correlation), ct);
    private static bool CanonicalToken(string token) => token.Length == 43
        && token.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')
        && "AEIMQUYcgkosw048".Contains(token[^1]);
    private static ProfileOperationException Limited() => new("profile_rate_limited", 429);
}
