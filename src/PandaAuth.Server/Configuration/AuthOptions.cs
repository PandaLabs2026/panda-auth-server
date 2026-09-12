namespace PandaAuth.Server.Configuration;

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>OIDC Issuer（生产由环境变量 Auth__Issuer 注入，如 https://auth.pandalabs.cn；国内/海外双实例零代码切换）。</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>是否强制 HTTPS（生产强制开启；本地开发可关闭）。</summary>
    public bool HttpsRequired { get; set; } = true;

    public RateLimitOptions RateLimit { get; set; } = new();

    public SigningKeyOptions Keys { get; set; } = new();

    public SeedOptions Seed { get; set; } = new();

    /// <summary>DataProtection 密钥持久化目录；为空时使用临时密钥（仅限开发环境）。</summary>
    public string DataProtectionKeyPath { get; set; } = string.Empty;
}

public sealed class RateLimitOptions
{
    /// <summary>同一 IP 每分钟允许的登录尝试次数。</summary>
    public int IpPerMinute { get; set; } = 10;

    /// <summary>同一账号每分钟允许的登录尝试次数。</summary>
    public int AccountPerMinute { get; set; } = 5;
}

public sealed class SigningKeyOptions
{
    /// <summary>签名密钥轮换周期（天）；启动时检测到最新密钥超出该周期即生成新密钥。</summary>
    public int RotationIntervalDays { get; set; } = 90;

    /// <summary>签名密钥总有效期（天），需大于轮换周期，保证旧密钥在旧 Access Token 过期前仍可验签。</summary>
    public int ValidityDays { get; set; } = 180;
}

public sealed class SeedOptions
{
    public bool Enabled { get; set; } = true;

    public string AdminEmail { get; set; } = "admin@pandalabs.cn";

    /// <summary>管理员初始密码；为空则跳过管理员账号创建。生产环境通过 Seed__AdminPassword 环境变量注入。</summary>
    public string AdminPassword { get; set; } = string.Empty;
}
