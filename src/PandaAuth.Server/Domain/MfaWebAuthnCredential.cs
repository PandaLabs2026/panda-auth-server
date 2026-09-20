namespace PandaAuth.Server.Domain;

/// <summary>管理员 WebAuthn 凭据的公开部分；私钥、PIN 与生物信息永不进入服务端。</summary>
public sealed class MfaWebAuthnCredential
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public byte[] CredentialId { get; set; } = [];
    public byte[] PublicKeyCose { get; set; } = [];
    public uint SignatureCounter { get; set; }
    public string? Aaguid { get; set; }
    public string? TransportsJson { get; set; }
    public bool BackupEligible { get; set; }
    public bool BackupState { get; set; }
    public string? FriendlyName { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
