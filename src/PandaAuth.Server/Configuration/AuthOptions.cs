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

    /// <summary>公开 Management API（/mgmt/v1/*）总开关；默认关闭，未启用时管理控制器不进路由模型。</summary>
    public MgmtOptions Mgmt { get; set; } = new();

    /// <summary>租户规范主机与 Fleet route revision；未登记主机默认拒绝。</summary>
    public TenantRoutingOptions TenantRouting { get; set; } = new();

    /// <summary>泄露密码检测（HIBP k-anonymity）；默认关闭——自托管部署可能没有稳定外网出口。</summary>
    public HibpOptions Hibp { get; set; } = new();

    /// <summary>登录路径 MFA 挑战；默认关闭——开启后已有活跃 TOTP/Passkey 因子的用户登录需完成第二因子挑战（2026-09-30 拍板）。</summary>
    public LoginMfaOptions LoginMfa { get; set; } = new();

    /// <summary>DataProtection 密钥持久化目录；为空时使用临时密钥（仅限开发环境）。</summary>
    public string DataProtectionKeyPath { get; set; } = string.Empty;
}

public sealed class RateLimitOptions
{
    /// <summary>同一 IP 每分钟允许的登录尝试次数。</summary>
    public int IpPerMinute { get; set; } = 10;

    /// <summary>同一账号每分钟允许的登录尝试次数。</summary>
    public int AccountPerMinute { get; set; } = 5;

    /// <summary>登录 MFA 挑战：同一 IP 每分钟允许的断言尝试次数（TOTP 六位码暴力破解需要持续多次尝试）。</summary>
    public int MfaChallengeIpPerMinute { get; set; } = 10;

    /// <summary>登录 MFA 挑战：同一用户每分钟允许的断言尝试次数。</summary>
    public int MfaChallengeAccountPerMinute { get; set; } = 5;
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

    public OasisWebSeedOptions OasisWeb { get; set; } = new();

    public FleetAdminWebSeedOptions FleetAdminWeb { get; set; } = new();

    public FleetSeedOptions Fleet { get; set; } = new();

    public MgmtSeedOptions Mgmt { get; set; } = new();

    public DemoSeedOptions Demo { get; set; } = new();
}

public sealed class AdminSeedOptions
{
    public string Email { get; set; } = "admin@example.com";

    /// <summary>管理员初始密码；为空则跳过管理员账号创建。生产环境通过 Auth__Seed__Admin__Password 环境变量注入。</summary>
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// 第一方机密 Web 客户端（BFF 形态：授权码 + PKCE + 刷新令牌）的共有种子配置。
/// me-web 与 admin-web 同构，共用 DbSeeder 的 upsert 播种路径；差异只有 clientId/DisplayName 与配置键前缀。
/// oasis-web 复用同一条 upsert 路径，但默认关闭且权限集更小（见 OasisWebSeedOptions）。
/// </summary>
public abstract class FirstPartyWebSeedOptions
{
    /// <summary>是否播种/订正该客户端；PandaAuth 自带面板（me-web/admin-web）默认开启。</summary>
    public virtual bool Enabled { get; set; } = true;

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

/// <summary>
/// Oasis 工作台（oasis.pandalabs.cn）的 Web 客户端：机密、授权码 + PKCE + 刷新令牌，
/// 走与 me-web 相同的 upsert 播种路径，但权限集裁掉 roles scope 与 Introspection 端点
/// （Oasis 不请求 roles，授权完全在本地；token 只存服务端 cookie，无内省消费方）。
/// 默认关闭——Oasis 不是 PandaAuth 自带面板，仅以 PandaAuth 为 IDP 的部署显式开启；
/// 社区自托管默认不播种（开启但缺 ClientSecret 时 migrate 失败关闭，与 Fleet/Mgmt 同策略）。
/// </summary>
public sealed class OasisWebSeedOptions : FirstPartyWebSeedOptions
{
    /// <summary>默认关闭；生产经 Auth__Seed__OasisWeb__Enabled 显式开启。</summary>
    public override bool Enabled { get; set; }
}

/// <summary>
/// Fleet 管理台（panda-fleet-admin，fleet-admin-web）的 Web 客户端：机密、授权码 + PKCE + 刷新令牌，
/// 走与 me-web 相同的 upsert 播种路径；权限集在第一方 Web 基础上追加 fleet.* 委托作用域
/// （见 DbSeeder.FleetAdminWebPermissions）。默认关闭——与 OasisWeb 同策略，
/// 仅 Fleet 控制面部署经 Auth__Seed__FleetAdminWeb__Enabled 显式开启。
/// </summary>
public sealed class FleetAdminWebSeedOptions : FirstPartyWebSeedOptions
{
    /// <summary>默认关闭；生产经 Auth__Seed__FleetAdminWeb__Enabled 显式开启。</summary>
    public override bool Enabled { get; set; }
}

public sealed class FleetSeedOptions
{
    /// <summary>是否播种 Fleet 平台级客户端；默认关闭，只有专用 PandaAuth 实例显式开启。</summary>
    public bool Enabled { get; set; }

    /// <summary>Fleet API 客户端凭据；只从专用控制面私密环境变量注入。</summary>
    public string ClientSecret { get; set; } = string.Empty;
}

public sealed class MgmtSeedOptions
{
    /// <summary>是否播种 Management API（mgmt.* scope 与 mgmt-api 机密客户端）；默认关闭，显式开启方可用。</summary>
    public bool Enabled { get; set; }

    /// <summary>mgmt-api 客户端凭据；只从私密环境变量注入（Auth__Seed__Mgmt__ClientSecret）。</summary>
    public string ClientSecret { get; set; } = string.Empty;
}

/// <summary>公开 Management API 的部署面开关：启动时一次性读取，运行期不热切换（改开关需重启进程）。</summary>
public sealed class MgmtOptions
{
    /// <summary>是否注册 /mgmt/v1/* 路由；默认关闭（fail-closed），未启用时端点对外等效不存在（404）。</summary>
    public bool Enabled { get; set; }

    public MgmtRateLimitOptions RateLimit { get; set; } = new();
}

/// <summary>Management API 限流配置：clientId 与 IP 双维固定窗口；P3 集群化时与登录限流一同替换为 Redis 实现。</summary>
public sealed class MgmtRateLimitOptions
{
    /// <summary>只读端点（列表/详情/用户查询）每分钟许可，clientId 与 IP 各一维。</summary>
    public int ReadPerMinute { get; set; } = 60;

    /// <summary>写端点（创建/更新/删除）每分钟许可，clientId 与 IP 各一维。</summary>
    public int WritePerMinute { get; set; } = 10;

    /// <summary>密钥端点（创建/重置密钥）的额外按 IP 严格许可（防 clientId/密钥枚举）。</summary>
    public int SecretPerMinute { get; set; } = 6;
}

/// <summary>
/// 泄露密码检测（HIBP k-anonymity）。设计决策（2026-09-28，见 gap-analysis 登记）：
/// 设置新密码路径（自助改密/邮箱重置）命中泄露库即拒绝；登录路径检测下一迭代接入；
/// 服务故障默认失败开放（不因外呼故障阻断用户），可配 FailClosed 收紧。
/// </summary>
public sealed class HibpOptions
{
    /// <summary>启用泄露密码检测；默认关闭。</summary>
    public bool Enabled { get; set; }

    /// <summary>调用 HIBP 失败（网络/超时/非 200）时拒绝操作（失败关闭）；默认 false = 失败开放。</summary>
    public bool FailClosed { get; set; }

    /// <summary>HIBP range API 基址；默认官方端点，可指向自建代理以规避外网不可达。</summary>
    public string ApiBase { get; set; } = "https://api.pwnedpasswords.com";

    /// <summary>外呼超时毫秒；超时按失败策略处理。</summary>
    public int TimeoutMs { get; set; } = 2000;
}

/// <summary>
/// 登录路径 MFA 挑战（2026-09-30 拍板，先于微信适配器实施；见设计稿
/// docs/superpowers/specs/2026-09-30-login-mfa-challenge-design.md）。
/// </summary>
public sealed class LoginMfaOptions
{
    /// <summary>总开关；默认关闭——与 HIBP/Mgmt 同策略，存量部署升级不突变登录行为。PandaAuth 生产验证后显式开启。</summary>
    public bool Enabled { get; set; }
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
