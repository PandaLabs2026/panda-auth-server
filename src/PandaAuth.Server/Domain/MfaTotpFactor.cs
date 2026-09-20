namespace PandaAuth.Server.Domain;

/// <summary>管理员 TOTP 备用因子；密钥只以版本化 AES-GCM 密文形式保存。</summary>
public sealed class MfaTotpFactor
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string KeyVersion { get; set; } = string.Empty;
    public byte[] Nonce { get; set; } = [];
    public byte[] Ciphertext { get; set; } = [];
    public byte[] Tag { get; set; } = [];
    public long? LastAcceptedTimeStep { get; set; }
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ConfirmedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
