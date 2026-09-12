namespace PandaAuth.Server.Domain;

public static class KeyUse
{
    public const string Signing = "sig";
    public const string Encryption = "enc";
}

/// <summary>OIDC 签名/加密密钥的持久化记录（JWKS 密钥轮换的基础）。</summary>
public class SigningKeyRecord
{
    /// <summary>JWKS 中的 kid。</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>密钥用途：<see cref="KeyUse.Signing"/> 或 <see cref="KeyUse.Encryption"/>。</summary>
    public string Use { get; set; } = KeyUse.Signing;

    /// <summary>JWS/JWE 算法标识（RS256 / RSA-OAEP-256）。</summary>
    public string Algorithm { get; set; } = "RS256";

    /// <summary>PKCS#8 私钥。</summary>
    public byte[] PrivateKey { get; set; } = [];

    public DateTimeOffset NotBefore { get; set; }

    public DateTimeOffset NotAfter { get; set; }

    public bool Retired { get; set; }
}
