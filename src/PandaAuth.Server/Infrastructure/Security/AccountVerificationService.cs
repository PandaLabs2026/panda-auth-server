using System.Security.Cryptography;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

public enum AccountVerificationError
{
    InvalidOrExpiredToken,
    TooManyAttempts,
    AccountUnavailable,
    EmailNotConfirmed,
    DuplicateEmail,
    InvalidTarget,
    PasswordPolicy,
    ConcurrentUpdate,
}

public enum AccountSecurityEvent
{
    EmailConfirmed,
    EmailChanged,
    PasswordReset,
}

public sealed record AccountSecurityEventMetadata(
    AccountSecurityEvent Type,
    string SubjectId,
    string NormalizedTarget,
    DateTimeOffset OccurredAt);

public sealed record AccountVerificationResult(
    bool Succeeded,
    AccountVerificationError? Error = null,
    AccountSecurityEventMetadata? SecurityEvent = null)
{
    public static AccountVerificationResult Success(AccountSecurityEventMetadata? securityEvent = null)
        => new(true, SecurityEvent: securityEvent);

    public static AccountVerificationResult Fail(AccountVerificationError error)
        => new(false, error);
}

/// <summary>
/// Owns account email proofs and password recovery tokens. Plaintext tokens leave this service
/// only through the email port; persistence stores SHA-256 hashes and all mutations consume the
/// token in the same SaveChanges transaction as the account state transition.
/// </summary>
public sealed class AccountVerificationService(
    PandaAuthDbContext db,
    UserService users,
    IEmailSender emailSender,
    TimeProvider clock)
{
    public const int TokenTtlMinutes = 20;
    public const int MaxAttempts = 5;

    public async Task<AccountVerificationResult> BeginEmailConfirmationAsync(
        string userId, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null || user.Status != UserStatus.Active || string.IsNullOrWhiteSpace(user.Email))
            return AccountVerificationResult.Fail(AccountVerificationError.AccountUnavailable);
        if (user.EmailConfirmed)
            return AccountVerificationResult.Success();

        if (await IsEmailIssuanceLimitedAsync(
                user.Id, AccountVerificationPurpose.EmailConfirmation,
                users.NormalizeEmail(user.Email)!, cancellationToken))
            return AccountVerificationResult.Success();

        var token = await IssueEmailVerificationAsync(
            user.Id, AccountVerificationPurpose.EmailConfirmation, user.Email, cancellationToken);
        var template = EmailTemplates.EmailConfirmation(token);
        await emailSender.SendAsync(user.Email, template.Subject, template.Html, cancellationToken);
        return AccountVerificationResult.Success();
    }

    public async Task<AccountVerificationResult> ConsumeEmailConfirmationAsync(
        string userId, string token, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null || user.Status != UserStatus.Active || string.IsNullOrWhiteSpace(user.Email))
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

        var normalizedTarget = users.NormalizeEmail(user.Email)!;
        var candidate = await FindEmailVerificationAsync(
            user.Id, AccountVerificationPurpose.EmailConfirmation, normalizedTarget, cancellationToken);
        var verification = await VerifyAsync(candidate, token, cancellationToken);
        if (verification is not null)
            return verification;

        var consumedAt = clock.GetUtcNow();
        if (db.Database.IsRelational())
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            if (!await TryConsumeEmailVerificationAsync(candidate!, consumedAt, cancellationToken))
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            user = await users.FindByIdAsync(user.Id);
            if (user is null || user.Status != UserStatus.Active)
                return AccountVerificationResult.Fail(AccountVerificationError.AccountUnavailable);
            user.EmailConfirmed = true;
            var update = await users.UpdateAsync(user);
            if (!update.Succeeded)
                return MapAccountFailure(update, candidate!);
            await transaction.CommitAsync(cancellationToken);
        }
        else
        {
            if (!await TryConsumeEmailVerificationAsync(candidate!, consumedAt, cancellationToken))
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            user = await users.FindByIdAsync(user.Id);
            if (user is null || user.Status != UserStatus.Active)
                return AccountVerificationResult.Fail(AccountVerificationError.AccountUnavailable);
            user.EmailConfirmed = true;
            var update = await users.UpdateAsync(user);
            if (!update.Succeeded)
                return MapAccountFailure(update, candidate!);
        }

        return AccountVerificationResult.Success(new(
            AccountSecurityEvent.EmailConfirmed, user.Id, normalizedTarget, clock.GetUtcNow()));
    }

    public async Task<AccountVerificationResult> BeginEmailChangeAsync(
        string userId, string newEmail, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null || user.Status != UserStatus.Active)
            return AccountVerificationResult.Fail(AccountVerificationError.AccountUnavailable);
        if (!user.EmailConfirmed)
            return AccountVerificationResult.Fail(AccountVerificationError.EmailNotConfirmed);

        newEmail = newEmail.Trim();
        var normalizedTarget = users.NormalizeEmail(newEmail);
        if (string.IsNullOrWhiteSpace(normalizedTarget) || newEmail.Length > 256 ||
            !new EmailAddressAttribute().IsValid(newEmail))
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidTarget);
        if (await users.Users.AnyAsync(
                candidate => candidate.Id != user.Id && candidate.NormalizedEmail == normalizedTarget,
                cancellationToken))
            return AccountVerificationResult.Fail(AccountVerificationError.DuplicateEmail);

        if (await IsEmailIssuanceLimitedAsync(
                user.Id, AccountVerificationPurpose.EmailChange, normalizedTarget, cancellationToken))
            return AccountVerificationResult.Success();

        var token = await IssueEmailVerificationAsync(
            user.Id, AccountVerificationPurpose.EmailChange, newEmail.Trim(), cancellationToken);
        var template = EmailTemplates.EmailChange(token);
        await emailSender.SendAsync(newEmail.Trim(), template.Subject, template.Html, cancellationToken);
        return AccountVerificationResult.Success();
    }

    public async Task<AccountVerificationResult> ConsumeEmailChangeAsync(
        string userId, string newEmail, string token, CancellationToken cancellationToken = default)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null || user.Status != UserStatus.Active || !user.EmailConfirmed)
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

        newEmail = newEmail.Trim();
        var normalizedTarget = users.NormalizeEmail(newEmail);
        if (string.IsNullOrWhiteSpace(normalizedTarget))
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
        var candidate = await FindEmailVerificationAsync(
            user.Id, AccountVerificationPurpose.EmailChange, normalizedTarget, cancellationToken);
        var verification = await VerifyAsync(candidate, token, cancellationToken);
        if (verification is not null)
            return verification;

        var consumedAt = clock.GetUtcNow();
        if (db.Database.IsRelational())
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            if (!await TryConsumeEmailVerificationAsync(candidate!, consumedAt, cancellationToken))
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            user = await users.FindByIdAsync(user.Id);
            if (user is null || user.Status != UserStatus.Active || !user.EmailConfirmed)
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
            user.Email = newEmail.Trim();
            user.EmailConfirmed = true;
            user.SecurityStamp = Guid.NewGuid().ToString();
            var update = await users.UpdateAsync(user);
            if (!update.Succeeded)
                return MapAccountFailure(update, candidate!);
            await transaction.CommitAsync(cancellationToken);
        }
        else
        {
            if (!await TryConsumeEmailVerificationAsync(candidate!, consumedAt, cancellationToken))
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            user = await users.FindByIdAsync(user.Id);
            if (user is null || user.Status != UserStatus.Active || !user.EmailConfirmed)
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
            user.Email = newEmail.Trim();
            user.EmailConfirmed = true;
            user.SecurityStamp = Guid.NewGuid().ToString();
            var update = await users.UpdateAsync(user);
            if (!update.Succeeded)
                return MapAccountFailure(update, candidate!);
        }

        return AccountVerificationResult.Success(new(
            AccountSecurityEvent.EmailChanged, user.Id, normalizedTarget, clock.GetUtcNow()));
    }

    public async Task<AccountVerificationResult> BeginPasswordResetAsync(
        string email, CancellationToken cancellationToken = default)
    {
        email = email.Trim();
        var normalizedTarget = users.NormalizeEmail(email) ?? string.Empty;
        var now = clock.GetUtcNow();
        // Same per-target issuance gate for known and unknown addresses; no enumeration via result.
        if (await db.PasswordResetRequests.AnyAsync(request =>
                request.NormalizedTarget == normalizedTarget && request.CreatedAt > now.AddMinutes(-1),
                cancellationToken))
            return AccountVerificationResult.Success();
        if (await db.PasswordResetRequests.CountAsync(request =>
                request.NormalizedTarget == normalizedTarget && request.CreatedAt > now.AddHours(-1),
                cancellationToken) >= 5)
            return AccountVerificationResult.Success();
        var user = await users.FindByEmailAsync(email);
        var eligible = user is { Status: UserStatus.Active, EmailConfirmed: true };
        var token = NewToken();
        // Supersede every previous proof for this target in the issuance transaction.
        var previous = await db.PasswordResetRequests
            .Where(request => request.Purpose == PasswordResetPurpose.PasswordReset &&
                              request.NormalizedTarget == normalizedTarget && request.ConsumedAt == null)
            .ToListAsync(cancellationToken);
        foreach (var request in previous)
            request.ConsumedAt = now;
        db.PasswordResetRequests.Add(new PasswordResetRequest
        {
            Purpose = PasswordResetPurpose.PasswordReset,
            SubjectId = eligible ? user!.Id : null,
            NormalizedTarget = normalizedTarget,
            TokenHash = VerificationHasher.TokenHash(token),
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(TokenTtlMinutes),
        });
        await db.SaveChangesAsync(cancellationToken);

        if (eligible)
        {
            var template = EmailTemplates.PasswordReset(token);
            await emailSender.SendAsync(user!.Email!, template.Subject, template.Html, cancellationToken);
        }

        // The result deliberately has the same shape for known, unknown and ineligible accounts.
        return AccountVerificationResult.Success();
    }

    public async Task<AccountVerificationResult> ConsumePasswordResetAsync(
        string email, string token, string newPassword, CancellationToken cancellationToken = default)
    {
        var normalizedTarget = users.NormalizeEmail(email.Trim()) ?? string.Empty;
        var candidate = await db.PasswordResetRequests
            .Where(request => request.Purpose == PasswordResetPurpose.PasswordReset &&
                              request.NormalizedTarget == normalizedTarget && request.ConsumedAt == null)
            .OrderByDescending(request => request.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);
        var verification = await VerifyAsync(candidate, token, cancellationToken);
        if (verification is not null)
            return verification;
        if (candidate!.SubjectId is null)
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

        var passwordValidation = UserService.ValidatePassword(newPassword);
        if (!passwordValidation.Succeeded)
            return MapAccountFailure(passwordValidation, candidate);

        var consumedAt = clock.GetUtcNow();
        if (db.Database.IsRelational())
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            if (!await TryConsumePasswordResetAsync(candidate, consumedAt, cancellationToken))
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            var user = await users.FindByIdAsync(candidate.SubjectId);
            if (user is null || user.Status != UserStatus.Active || !user.EmailConfirmed ||
                user.NormalizedEmail != normalizedTarget)
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            // Two independently issued proofs can race. A successful reset consumes all outstanding
            // proofs for the address before the account mutation commits.
            await db.PasswordResetRequests
                .Where(request => request.Purpose == PasswordResetPurpose.PasswordReset &&
                                  request.NormalizedTarget == normalizedTarget && request.ConsumedAt == null &&
                                  request.Id != candidate.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(request => request.ConsumedAt, consumedAt), cancellationToken);
            var update = await users.ReplacePasswordAsync(user, newPassword);
            if (!update.Succeeded)
                return MapAccountFailure(update, candidate);
            await transaction.CommitAsync(cancellationToken);
        }
        else
        {
            if (!await TryConsumePasswordResetAsync(candidate, consumedAt, cancellationToken))
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            var user = await users.FindByIdAsync(candidate.SubjectId);
            if (user is null || user.Status != UserStatus.Active || !user.EmailConfirmed ||
                user.NormalizedEmail != normalizedTarget)
                return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);

            var outstanding = await db.PasswordResetRequests
                .Where(request => request.Purpose == PasswordResetPurpose.PasswordReset &&
                                  request.NormalizedTarget == normalizedTarget && request.ConsumedAt == null &&
                                  request.Id != candidate.Id)
                .ToListAsync(cancellationToken);
            foreach (var request in outstanding)
                request.ConsumedAt = consumedAt;
            var update = await users.ReplacePasswordAsync(user, newPassword);
            if (!update.Succeeded)
                return MapAccountFailure(update, candidate);
        }

        return AccountVerificationResult.Success(new(
            AccountSecurityEvent.PasswordReset, candidate.SubjectId, normalizedTarget, clock.GetUtcNow()));
    }

    private async Task<string> IssueEmailVerificationAsync(
        string subjectId,
        AccountVerificationPurpose purpose,
        string target,
        CancellationToken cancellationToken)
    {
        var token = NewToken();
        var now = clock.GetUtcNow();
        var normalizedTarget = users.NormalizeEmail(target)!;
        var previous = await db.EmailVerifications
            .Where(item => item.SubjectId == subjectId && item.Purpose == purpose &&
                           item.ConsumedAt == null)
            .ToListAsync(cancellationToken);
        foreach (var item in previous)
            item.ConsumedAt = now;

        db.EmailVerifications.Add(new EmailVerification
        {
            Purpose = purpose,
            SubjectId = subjectId,
            NormalizedTarget = normalizedTarget,
            TokenHash = VerificationHasher.TokenHash(token),
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(TokenTtlMinutes),
        });
        await db.SaveChangesAsync(cancellationToken);
        return token;
    }

    private async Task<bool> IsEmailIssuanceLimitedAsync(
        string subjectId, AccountVerificationPurpose purpose, string normalizedTarget,
        CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        var query = db.EmailVerifications.Where(item =>
            item.SubjectId == subjectId && item.Purpose == purpose &&
            item.NormalizedTarget == normalizedTarget);
        return await query.AnyAsync(item => item.CreatedAt > now.AddMinutes(-1), cancellationToken)
            || await query.CountAsync(item => item.CreatedAt > now.AddHours(-1), cancellationToken) >= 5;
    }

    private Task<EmailVerification?> FindEmailVerificationAsync(
        string subjectId,
        AccountVerificationPurpose purpose,
        string normalizedTarget,
        CancellationToken cancellationToken)
        => db.EmailVerifications
            .Where(item => item.SubjectId == subjectId && item.Purpose == purpose &&
                           item.NormalizedTarget == normalizedTarget && item.ConsumedAt == null)
            .OrderByDescending(item => item.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

    private async Task<AccountVerificationResult?> VerifyAsync(
        EmailVerification? candidate, string token, CancellationToken cancellationToken)
    {
        if (candidate is null || candidate.ExpiresAt <= clock.GetUtcNow())
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
        if (candidate.Attempts >= MaxAttempts)
            return AccountVerificationResult.Fail(AccountVerificationError.TooManyAttempts);
        if (TokenMatches(candidate.TokenHash, token))
            return null;

        if (!db.Database.IsRelational())
        {
            candidate.Attempts++;
            await db.SaveChangesAsync(cancellationToken);
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var updated = await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE panda_email_verifications
            SET "Attempts" = "Attempts" + 1
            WHERE "Id" = {candidate.Id}
              AND "ConsumedAt" IS NULL
              AND "Attempts" < {MaxAttempts}
            """, cancellationToken);
        db.ChangeTracker.Clear();
        await transaction.CommitAsync(cancellationToken);
        if (updated == 0)
            return AccountVerificationResult.Fail(AccountVerificationError.TooManyAttempts);
        return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
    }

    private async Task<AccountVerificationResult?> VerifyAsync(
        PasswordResetRequest? candidate, string token, CancellationToken cancellationToken)
    {
        if (candidate is null || candidate.ExpiresAt <= clock.GetUtcNow())
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
        if (candidate.Attempts >= MaxAttempts)
            return AccountVerificationResult.Fail(AccountVerificationError.TooManyAttempts);
        if (TokenMatches(candidate.TokenHash, token))
            return null;

        if (!db.Database.IsRelational())
        {
            candidate.Attempts++;
            await db.SaveChangesAsync(cancellationToken);
            return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var updated = await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE panda_password_reset_requests
            SET "Attempts" = "Attempts" + 1
            WHERE "Id" = {candidate.Id}
              AND "ConsumedAt" IS NULL
              AND "Attempts" < {MaxAttempts}
            """, cancellationToken);
        db.ChangeTracker.Clear();
        await transaction.CommitAsync(cancellationToken);
        if (updated == 0)
            return AccountVerificationResult.Fail(AccountVerificationError.TooManyAttempts);
        return AccountVerificationResult.Fail(AccountVerificationError.InvalidOrExpiredToken);
    }

    private async Task<bool> TryConsumeEmailVerificationAsync(
        EmailVerification candidate, DateTimeOffset consumedAt, CancellationToken cancellationToken)
    {
        if (!db.Database.IsRelational())
        {
            candidate.ConsumedAt = consumedAt;
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }

        var updated = await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE panda_email_verifications
            SET "ConsumedAt" = {consumedAt}
            WHERE "Id" = {candidate.Id}
              AND "ConsumedAt" IS NULL
              AND "ExpiresAt" > {consumedAt}
              AND "Attempts" < {MaxAttempts}
            """, cancellationToken);
        db.ChangeTracker.Clear();
        return updated == 1;
    }

    private async Task<bool> TryConsumePasswordResetAsync(
        PasswordResetRequest candidate, DateTimeOffset consumedAt, CancellationToken cancellationToken)
    {
        if (!db.Database.IsRelational())
        {
            candidate.ConsumedAt = consumedAt;
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }

        var updated = await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE panda_password_reset_requests
            SET "ConsumedAt" = {consumedAt}
            WHERE "Id" = {candidate.Id}
              AND "ConsumedAt" IS NULL
              AND "ExpiresAt" > {consumedAt}
              AND "Attempts" < {MaxAttempts}
            """, cancellationToken);
        db.ChangeTracker.Clear();
        return updated == 1;
    }

    private AccountVerificationResult MapAccountFailure(
        AccountResult result, EmailVerification candidate)
    {
        db.ChangeTracker.Clear();
        return AccountVerificationResult.Fail(result.Errors.Any(error =>
            error.Code is "DuplicateEmail" or "DuplicateAccount")
                ? AccountVerificationError.DuplicateEmail
                : AccountVerificationError.ConcurrentUpdate);
    }

    private AccountVerificationResult MapAccountFailure(
        AccountResult result, PasswordResetRequest candidate)
    {
        db.ChangeTracker.Clear();
        return AccountVerificationResult.Fail(result.Errors.Any(error => error.Code == "PasswordPolicy")
            ? AccountVerificationError.PasswordPolicy
            : AccountVerificationError.ConcurrentUpdate);
    }

    private static string NewToken() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    private static bool TokenMatches(string expectedHash, string token)
    {
        var actualHash = VerificationHasher.TokenHash(token);
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(expectedHash), Convert.FromHexString(actualHash));
    }
}
