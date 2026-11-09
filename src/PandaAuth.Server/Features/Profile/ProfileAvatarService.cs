using System.Buffers.Binary;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

public sealed record PrivateAvatar(ProfileAvatar Avatar, string Revision);

public sealed class ProfileAvatarService(PandaAuthDbContext db, SelfProfileService profiles,
    ProfileAvatarDecoder decoder, SecurityEventWriter audit, TimeProvider clock)
{
    public async Task<PrivateAvatar> ReadAsync(string actor, CancellationToken ct = default)
    {
        var result = await (from user in db.Users.AsNoTracking()
            where user.Id == actor && user.Status == UserStatus.Active
            join profile in db.UserProfiles.AsNoTracking() on user.Id equals profile.UserId
            join avatar in db.ProfileAvatars.AsNoTracking() on user.Id equals avatar.UserId
            select new PrivateAvatar(avatar, "\"" + profile.Revision + "\"")).SingleOrDefaultAsync(ct);
        return result ?? throw new ProfileOperationException("profile_unavailable", 404);
    }

    public async Task<SelfProfileDto> PutAsync(string actor, string revision,
        Func<CancellationToken, Task<byte[]>> read, string correlation, CancellationToken ct = default)
    {
        var png = await decoder.DecodeAsync(async token =>
        {
            await ChargeAsync(actor, revision, correlation, token);
            return await read(token);
        }, ct);
        var width = checked((int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(16, 4)));
        var height = checked((int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(20, 4)));
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var write = await profiles.PrepareWriteAsync(actor, revision, ct);
        await profiles.PersistWriteAsync(write, ct);
        var now = clock.GetUtcNow();
        var changed = await db.ProfileAvatars.Where(a => a.UserId == actor).ExecuteUpdateAsync(s => s
            .SetProperty(a => a.Bytes, png).SetProperty(a => a.Width, width).SetProperty(a => a.Height, height)
            .SetProperty(a => a.UpdatedAt, now), ct);
        if (changed == 0) db.ProfileAvatars.Add(new ProfileAvatar { UserId = actor, Bytes = png, Width = width, Height = height, UpdatedAt = now });
        await RecordAsync(actor, "profile.avatar.updated", correlation, ct);
        var result = await profiles.ReadAsync(actor, ct);
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<SelfProfileDto> DeleteAsync(string actor, string revision, string correlation, CancellationToken ct = default)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var write = await profiles.PrepareWriteAsync(actor, revision, ct);
        await profiles.PersistWriteAsync(write, ct);
        await db.ProfileAvatars.Where(a => a.UserId == actor).ExecuteDeleteAsync(ct);
        await RecordAsync(actor, "profile.avatar.deleted", correlation, ct);
        var result = await profiles.ReadAsync(actor, ct);
        await transaction.CommitAsync(ct);
        return result;
    }

    private async Task ChargeAsync(string actor, string revision, string correlation, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await profiles.PrepareWriteAsync(actor, revision, ct);
        var rate = await db.ProfileRateLimits.AsNoTracking().SingleOrDefaultAsync(r => r.UserId == actor, ct)
            ?? new ProfileRateLimit { UserId = actor };
        var now = clock.GetUtcNow();
        if (rate.AvatarWindowStart is null || now >= rate.AvatarWindowStart.Value.AddMinutes(1))
        { rate.AvatarWindowStart = now; rate.AvatarCount = 0; }
        if (rate.AvatarCount >= 2) throw new ProfileOperationException("profile_rate_limited", 429);
        rate.AvatarCount++;
        var changed = await db.ProfileRateLimits.Where(r => r.UserId == actor).ExecuteUpdateAsync(s => s
            .SetProperty(r => r.AvatarWindowStart, rate.AvatarWindowStart).SetProperty(r => r.AvatarCount, rate.AvatarCount), ct);
        if (changed == 0) db.ProfileRateLimits.Add(rate);
        await RecordAsync(actor, "profile.avatar.upload.accepted", correlation, ct);
        await transaction.CommitAsync(ct);
    }

    private Task RecordAsync(string actor, string kind, string correlation, CancellationToken ct)
        => audit.RecordAsync(new SecurityEventEntry(kind, actor, actor, "profile", null, null,
            new { fields = new[] { "avatar" } }, null, null, correlation), ct);
}
