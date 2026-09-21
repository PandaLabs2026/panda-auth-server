using System.Security.Cryptography;
using System.Text;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// 验证码链路的两个哈希口径（移植自 panda-asst-server 的 EmailProtector.Hash / Hasher.Sha256Hex）：
/// 邮箱哈希用作频控与检索键（大小写不敏感），验证码哈希用于入库比对（明文不落库）。
/// 均为无盐 SHA256——键的目的是检索与等值比对（非口令抗暴破），验证码本身有 5 分钟 TTL、
/// 5 次失败锁定与双频控兜底。
/// </summary>
public static class VerificationHasher
{
    /// <summary>邮箱规范化（trim + 小写）后 SHA256——与 Identity 的邮箱规范化口径一致。</summary>
    public static string EmailHash(string email)
        => Sha256Hex(email.Trim().ToLowerInvariant());

    /// <summary>验证码 SHA256（六位数字，等值比对）。</summary>
    public static string CodeHash(string code)
        => Sha256Hex(code);

    /// <summary>Hash for high-entropy one-time account verification and recovery tokens.</summary>
    public static string TokenHash(string token)
        => Sha256Hex(token);

    private static string Sha256Hex(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(hash);
    }
}
