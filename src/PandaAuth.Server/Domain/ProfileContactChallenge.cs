namespace PandaAuth.Server.Domain;

public enum ProfileContactChallengeState { PendingDelivery, Delivered, Consumed, Failed, Expired, Superseded }

/// <summary>Contact proof is independent of login/recovery verification. Never persist the plaintext token.</summary>
public sealed class ProfileContactChallenge
{
    public Guid Id { get; set; }
    public required string UserId { get; set; }
    public required string Address { get; set; }
    public required byte[] TokenDigest { get; set; }
    public required string ExpectedRevision { get; set; }
    public Guid DeliveryId { get; set; }
    public ProfileContactChallengeState State { get; set; }
    public int FailedAttempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

/// <summary>Account-wide limits survive challenge replacement and process restart.</summary>
public sealed class ProfileRateLimit
{
    public required string UserId { get; set; }
    public DateTimeOffset? CreationWindowStart { get; set; }
    public int CreationCount { get; set; }
    public DateTimeOffset? LastChallengeAt { get; set; }
    public DateTimeOffset? ConfirmationWindowStart { get; set; }
    public int ConfirmationCount { get; set; }
}
