using Microsoft.Extensions.Caching.Memory;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public sealed record MfaChallenge(byte[] Value, DateTimeOffset ExpiresAt);

public sealed class MfaChallengeStore(IMemoryCache cache, TimeProvider clock)
{
    private readonly object consumeLock = new();

    public Task<Guid> CreateAsync(
        string purpose,
        string subject,
        byte[] value,
        TimeSpan lifetime,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
        cancellationToken.ThrowIfCancellationRequested();

        var id = Guid.NewGuid();
        var expiresAt = clock.GetUtcNow().Add(lifetime);
        cache.Set(Key(id), new StoredChallenge(purpose, subject, [.. value], expiresAt), expiresAt);
        return Task.FromResult(id);
    }

    public Task<MfaChallenge?> ConsumeAsync(
        Guid id,
        string purpose,
        string subject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (consumeLock)
        {
            if (!cache.TryGetValue<StoredChallenge>(Key(id), out var stored) || stored is null ||
                stored.ExpiresAt <= clock.GetUtcNow() ||
                !string.Equals(stored.Purpose, purpose, StringComparison.Ordinal) ||
                !string.Equals(stored.Subject, subject, StringComparison.Ordinal))
            {
                return Task.FromResult<MfaChallenge?>(null);
            }

            cache.Remove(Key(id));
            return Task.FromResult<MfaChallenge?>(new MfaChallenge([.. stored.Value], stored.ExpiresAt));
        }
    }

    private static string Key(Guid id) => $"panda:mfa:challenge:{id:N}";

    private sealed record StoredChallenge(string Purpose, string Subject, byte[] Value, DateTimeOffset ExpiresAt);
}
