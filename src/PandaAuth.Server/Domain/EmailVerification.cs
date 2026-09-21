namespace PandaAuth.Server.Domain;

public enum AccountVerificationPurpose
{
    EmailConfirmation,
    EmailChange,
}

/// <summary>One-time proof for confirming the current email or a pending replacement email.</summary>
public sealed class EmailVerification
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public AccountVerificationPurpose Purpose { get; set; }
    public required string SubjectId { get; set; }
    public required string NormalizedTarget { get; set; }
    public required string TokenHash { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
