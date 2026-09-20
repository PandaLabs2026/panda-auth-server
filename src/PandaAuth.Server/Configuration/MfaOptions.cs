using System.Security.Cryptography;

namespace PandaAuth.Server.Configuration;

public sealed class MfaOptions
{
    public string TotpEncryptionKey { get; set; } = string.Empty;
    public string TotpKeyVersion { get; set; } = "v1";

    public void Validate(bool production)
    {
        if (TotpKeyVersion.Length is < 1 or > 32)
        {
            throw new InvalidOperationException("Auth:Mfa:TotpKeyVersion 必须为 1 到 32 个字符。");
        }

        if (string.IsNullOrWhiteSpace(TotpEncryptionKey))
        {
            if (production)
            {
                throw new InvalidOperationException("生产环境必须配置 Auth:Mfa:TotpEncryptionKey。");
            }

            return;
        }

        try
        {
            if (Convert.FromBase64String(TotpEncryptionKey).Length != 32)
            {
                throw new InvalidOperationException("Auth:Mfa:TotpEncryptionKey 解码后必须为 32 字节。");
            }
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException("Auth:Mfa:TotpEncryptionKey 必须为 Base64。", exception);
        }
    }

    public byte[] GetEncryptionKey(bool production)
    {
        Validate(production);
        return string.IsNullOrWhiteSpace(TotpEncryptionKey)
            ? RandomNumberGenerator.GetBytes(32)
            : Convert.FromBase64String(TotpEncryptionKey);
    }
}
