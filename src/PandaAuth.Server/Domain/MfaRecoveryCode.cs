namespace PandaAuth.Server.Domain;

/// <summary>Single-use MFA recovery code; plaintext is returned only at generation time.</summary>
public sealed class MfaRecoveryCode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public string CodeHash { get; set; } = string.Empty;
    public string Salt { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ConsumedAt { get; set; }
}
