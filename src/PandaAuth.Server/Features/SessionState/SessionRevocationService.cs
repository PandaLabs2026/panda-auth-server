using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.SessionState;

public sealed class SessionRevocationService(PandaAuthDbContext db, TimeProvider clock)
{
    private const int MaxSessionIdLength = 256;

    public async Task<bool> IsRevokedAsync(string clientId, string sessionId, CancellationToken cancellationToken)
    {
        var retention = GetRetention(clientId);
        var hash = HashSessionId(clientId, sessionId);
        var record = await db.SessionRevocations.FindAsync([clientId, hash], cancellationToken);
        return record is not null && record.ExpiresAt > clock.GetUtcNow() && retention > TimeSpan.Zero;
    }

    public async Task RevokeAsync(string clientId, string sessionId, CancellationToken cancellationToken)
    {
        var retention = GetRetention(clientId);
        var hash = HashSessionId(clientId, sessionId);
        var expiresAt = clock.GetUtcNow().Add(retention);
        var record = await db.SessionRevocations.FindAsync([clientId, hash], cancellationToken);
        if (record is null)
        {
            db.SessionRevocations.Add(new SessionRevocation
            {
                ClientId = clientId,
                SessionIdHash = hash,
                ExpiresAt = expiresAt,
            });
        }
        else if (record.ExpiresAt < expiresAt)
        {
            record.ExpiresAt = expiresAt;
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<int> DeleteExpiredBatchAsync(CancellationToken cancellationToken)
    {
        var expired = await db.SessionRevocations
            .Where(item => item.ExpiresAt <= clock.GetUtcNow())
            .OrderBy(item => item.ExpiresAt)
            .Take(500)
            .ToListAsync(cancellationToken);
        if (expired.Count == 0) return 0;

        db.SessionRevocations.RemoveRange(expired);
        await db.SaveChangesAsync(cancellationToken);
        return expired.Count;
    }

    public static string HashSessionId(string clientId, string sessionId)
    {
        _ = GetRetention(clientId);
        if (string.IsNullOrWhiteSpace(sessionId) || sessionId.Length > MaxSessionIdLength)
        {
            throw new ArgumentException("A valid session identifier is required.", nameof(sessionId));
        }

        var bytes = Encoding.UTF8.GetBytes($"{clientId}\0{sessionId}");
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static TimeSpan GetRetention(string clientId) => clientId switch
    {
        PandaAuthSessionApi.AdminClientId => PandaAuthSessionApi.AdminAbsoluteLifetime,
        PandaAuthSessionApi.MeClientId => PandaAuthSessionApi.MeAbsoluteLifetime,
        _ => throw new ArgumentException("The client is not authorized for session revocation.", nameof(clientId)),
    };
}
