using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed record ExternalIdentityResult(bool Succeeded, string? ErrorCode = null, string? Error = null, ExternalIdentity? Identity = null)
{
    public static ExternalIdentityResult Success(ExternalIdentity identity) => new(true, Identity: identity);
    public static ExternalIdentityResult Failure(string code, string message) => new(false, code, message);
}

public sealed record ExternalIdentityProfile(
    string Provider,
    string ProviderSubject,
    string? DisplayName,
    string? EmailSnapshot);

/// <summary>
/// Provider-neutral external identity association. Provider callback validation belongs to a future adapter.
/// </summary>
public sealed class ExternalIdentityService(
    PandaAuthDbContext db,
    TimeProvider clock,
    SecurityEventWriter? securityEvents = null,
    SessionSecurityService? sessionSecurity = null)
{
    public Task<List<ExternalIdentity>> ListActiveAsync(
        string userId, CancellationToken cancellationToken = default)
        => db.ExternalIdentities
            .Where(item => item.UserId == userId && item.UnlinkedAt == null)
            .OrderBy(item => item.Provider)
            .ThenBy(item => item.Id)
            .ToListAsync(cancellationToken);

    public Task<ExternalIdentityResult> BindVerifiedAsync(
        string userId,
        ExternalIdentityProfile profile,
        CancellationToken cancellationToken = default)
        => BindAsync(userId, profile.Provider, profile.ProviderSubject,
            profile.DisplayName, profile.EmailSnapshot, cancellationToken);

    public async Task<ExternalIdentityResult> BindAsync(
        string userId,
        string provider,
        string providerSubject,
        string? displayName,
        string? emailSnapshot,
        CancellationToken cancellationToken = default)
    {
        var validation = Validate(provider, providerSubject);
        if (validation is not null) return validation;
        var user = await db.Users.SingleOrDefaultAsync(item => item.Id == userId, cancellationToken);
        if (user is null || user.Status != UserStatus.Active)
            return ExternalIdentityResult.Failure("UserNotFound", "User does not exist or is inactive.");

        provider = NormalizeProvider(provider);
        if (await db.ExternalIdentities.AnyAsync(item => item.Provider == provider &&
            item.ProviderSubject == providerSubject && item.UnlinkedAt == null, cancellationToken))
            return ExternalIdentityResult.Failure("ExternalIdentityAlreadyLinked", "External identity is already linked.");

        var now = clock.GetUtcNow();
        var identity = new ExternalIdentity
        {
            UserId = userId,
            Provider = provider,
            ProviderSubject = providerSubject,
            DisplayName = displayName,
            EmailSnapshot = emailSnapshot,
            LinkedAt = now,
            UpdatedAt = now,
        };
        db.ExternalIdentities.Add(identity);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            if (securityEvents is not null)
            {
                await securityEvents.RecordAsync(new SecurityEventEntry(
                    "user.external_identity_linked",
                    userId,
                    userId,
                    "external_identity",
                    identity.Id.ToString(),
                    "external_identity",
                    new { provider, providerSubject, hasEmailSnapshot = emailSnapshot is not null },
                    null,
                    null,
                    null), cancellationToken);
            }
            return ExternalIdentityResult.Success(identity);
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            return ExternalIdentityResult.Failure("ExternalIdentityAlreadyLinked", "External identity is already linked.");
        }
    }

    public Task<ExternalIdentity?> FindActiveAsync(string provider, string providerSubject, CancellationToken cancellationToken = default)
        => db.ExternalIdentities.SingleOrDefaultAsync(item => item.Provider == NormalizeProvider(provider) &&
            item.ProviderSubject == providerSubject && item.UnlinkedAt == null, cancellationToken);

    /// <summary>
    /// Records a successful provider authentication without emitting a security event
    /// for every login. Provider adapters call this only after validating the provider
    /// assertion and resolving the active link.
    /// </summary>
    public async Task<ExternalIdentity?> MarkUsedAsync(
        string provider,
        string providerSubject,
        CancellationToken cancellationToken = default)
    {
        var identity = await FindActiveAsync(provider, providerSubject, cancellationToken);
        if (identity is null) return null;

        var now = clock.GetUtcNow();
        identity.LastUsedAt = now;
        identity.UpdatedAt = now;
        await db.SaveChangesAsync(cancellationToken);
        return identity;
    }

    public async Task<ExternalIdentityResult> UnbindAsync(
        string userId, long identityId, CancellationToken cancellationToken = default)
    {
        var identity = await db.ExternalIdentities.SingleOrDefaultAsync(item => item.Id == identityId &&
            item.UserId == userId && item.UnlinkedAt == null, cancellationToken);
        if (identity is null) return ExternalIdentityResult.Failure("ExternalIdentityNotFound", "External identity does not exist.");

        var user = await db.Users.SingleOrDefaultAsync(item => item.Id == userId, cancellationToken);
        var hasPassword = !string.IsNullOrEmpty(user?.PasswordHash);
        var hasAnotherIdentity = await db.ExternalIdentities.AnyAsync(item => item.UserId == userId &&
            item.Id != identityId && item.UnlinkedAt == null, cancellationToken);
        if (!hasPassword && !hasAnotherIdentity)
            return ExternalIdentityResult.Failure("LastLoginMethod", "Cannot remove the last available login method.");

        identity.UnlinkedAt = identity.UpdatedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(cancellationToken);
        if (sessionSecurity is not null)
        {
            await sessionSecurity.InvalidateUserAsync(
                user!, "external_identity_unlinked", userId, cancellationToken);
        }
        if (securityEvents is not null)
        {
            await securityEvents.RecordAsync(new SecurityEventEntry(
                "user.external_identity_unlinked",
                userId,
                userId,
                "external_identity",
                identity.Id.ToString(),
                "external_identity",
                new { provider = identity.Provider, providerSubject = identity.ProviderSubject },
                null,
                null,
                null), cancellationToken);
        }
        return ExternalIdentityResult.Success(identity);
    }

    private static string NormalizeProvider(string provider) => provider.Trim().ToLowerInvariant();

    private static ExternalIdentityResult? Validate(string provider, string providerSubject)
    {
        if (string.IsNullOrWhiteSpace(provider) || provider.Length > 64 || provider.Any(char.IsWhiteSpace))
            return ExternalIdentityResult.Failure("InvalidProvider", "Provider is required and cannot contain whitespace.");
        if (string.IsNullOrWhiteSpace(providerSubject) || providerSubject.Length > 450)
            return ExternalIdentityResult.Failure("InvalidProviderSubject", "Provider subject is required and must not exceed 450 characters.");
        return null;
    }
}
