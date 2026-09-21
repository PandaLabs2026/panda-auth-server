namespace PandaAuth.Server.Domain;

public enum PasswordResetPurpose
{
    PasswordReset,
}

/// <summary>
/// One-time password recovery proof. SubjectId is null for neutral requests targeting an
/// unknown, unconfirmed or unavailable account; those rows deliberately follow the same
/// persistence path without causing email delivery.
/// </summary>
public sealed class PasswordResetRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public PasswordResetPurpose Purpose { get; set; } = PasswordResetPurpose.PasswordReset;
    public string? SubjectId { get; set; }
    public required string NormalizedTarget { get; set; }
    public required string TokenHash { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
