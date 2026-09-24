namespace PandaAuth.Server.Configuration;

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>OIDC Issuer（生产由环境变量 Auth__Issuer 注入，如 https://auth.pandalabs.cn；国内/海外双实例零代码切换）。</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>是否强制 HTTPS（生产强制开启；本地开发可关闭）。</summary>
    public bool HttpsRequired { get; set; } = true;

    public RateLimitOptions RateLimit { get; set; } = new();

    public AuditOptions Audit { get; set; } = new();

    public SigningKeyOptions Keys { get; set; } = new();

    public SeedOptions Seed { get; set; } = new();

    public MfaOptions Mfa { get; set; } = new();

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

public sealed class AuditOptions
{
    /// <summary>
    /// 登录审计日志（login_logs）保留天数；超期记录由后台清理任务按天删除。
    /// 每次登录尝试（含失败）都会写一行，无保留期会被无界撑大。≤0 视为误配，清理任务会拒绝执行并告警。
    /// </summary>
    public int RetentionDays { get; set; } = 90;
}

public sealed class SigningKeyOptions
{
    /// <summary>签名密钥轮换周期（天）；启动时检测到最新密钥超出该周期即生成新密钥。</summary>
    public int RotationIntervalDays { get; set; } = 90;

    /// <summary>签名密钥总有效期（天），需大于轮换周期，保证旧密钥在旧 Access Token 过期前仍可验签。</summary>
    public int ValidityDays { get; set; } = 180;

    /// <summary>
    /// 启动期校验密钥周期配置，非法即失败关闭。
    /// 代码依赖「ValidityDays &gt; RotationIntervalDays」：轮换出新密钥后旧密钥在 NotAfter 之前必须仍可验签，
    /// 否则误配会让上一轮签发的 Access Token 在过期前验签失败（静默 401，无异常日志）。
    /// </summary>
    /// <exception cref="InvalidOperationException">RotationIntervalDays ≤ 0，或 ValidityDays ≤ RotationIntervalDays。</exception>
    public void Validate()
    {
        if (RotationIntervalDays <= 0 || ValidityDays <= RotationIntervalDays)
        {
            throw new InvalidOperationException(
                $"Auth:Keys 配置非法：RotationIntervalDays={RotationIntervalDays}、ValidityDays={ValidityDays}；" +
                "要求 RotationIntervalDays > 0 且 ValidityDays > RotationIntervalDays。" +
                "当前取值下旧签名密钥会在上一轮签发的 Access Token 过期前退役，导致验签静默失败。");
        }
    }
}

public sealed class SeedOptions
{
    /// <summary>总开关；false 时跳过全部种子数据（含管理员、me-web 与 demo 客户端）。</summary>
    public bool Enabled { get; set; } = true;

    public AdminSeedOptions Admin { get; set; } = new();

    public MeSeedOptions Me { get; set; } = new();

    public AdminWebSeedOptions AdminWeb { get; set; } = new();

    public DemoSeedOptions Demo { get; set; } = new();
}

public sealed class AdminSeedOptions
{
    public string Email { get; set; } = "admin@pandalabs.cc";

    /// <summary>管理员初始密码；为空则跳过管理员账号创建。生产环境通过 Auth__Seed__Admin__Password 环境变量注入。</summary>
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// 第一方机密 Web 客户端（BFF 形态：授权码 + PKCE + 刷新令牌）的共有种子配置。
/// me-web 与 admin-web 同构，共用 DbSeeder 的 upsert 播种路径；差异只有 clientId/DisplayName 与配置键前缀。
/// </summary>
public abstract class FirstPartyWebSeedOptions
{
    /// <summary>是否播种/订正该客户端；第一方客户端默认开启。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>客户端密钥；生产经环境变量注入（如 Auth__Seed__Me__ClientSecret）。</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>登录回调白名单；播种时必填，非空时整体替换存量值。</summary>
    public string[] RedirectUris { get; set; } = [];

    /// <summary>登出回跳白名单；播种时必填，非空时整体替换存量值。</summary>
    public string[] PostLogoutRedirectUris { get; set; } = [];
}

public sealed class MeSeedOptions : FirstPartyWebSeedOptions
{
}

public sealed class AdminWebSeedOptions : FirstPartyWebSeedOptions
{
}

public sealed class DemoSeedOptions
{
    /// <summary>是否播种演示客户端（demo-public/demo-web/demo-service）；默认关闭，生产一般不开启。</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>demo-web 机密客户端密钥；开启 Demo 播种时必填，经 Auth__Seed__Demo__WebSecret 注入。</summary>
    public string WebSecret { get; set; } = string.Empty;

    /// <summary>demo-service 机密客户端密钥；开启 Demo 播种时必填，经 Auth__Seed__Demo__ServiceSecret 注入。</summary>
    public string ServiceSecret { get; set; } = string.Empty;
}
