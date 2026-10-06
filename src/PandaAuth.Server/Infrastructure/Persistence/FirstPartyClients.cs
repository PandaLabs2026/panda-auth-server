namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>
/// PandaAuth 第一方/平台级 clientId 的单一事实源：DbSeeder 播种与宿主机命令
/// （WebsiteAdminClientCommand 注册 pandalabs-website-admin）管理的第一方客户端全集。
/// Management API 对该名单完全只读（ManagementClientsController.ReservedClientIds 由此派生）——
/// 自动化通道写入会误伤种子对账与第一方 BFF 依赖。新增第一方客户端必须同步登记；
/// 「播种集合 ⊆ 保留名单」的完整性由 PandaAuth.Tests 断言防漂移。
/// </summary>
public static class FirstPartyClients
{
    // ---- 第一方 Web BFF（授权码 + PKCE + 刷新；DbSeeder 播种）----
    public const string MeWeb = "me-web";
    public const string AdminWeb = "admin-web";
    public const string OasisWeb = "oasis-web";
    public const string FleetAdminWeb = "fleet-admin-web";
    public const string AsstWeb = "asst-web";
    public const string AsstAdmin = "asst-admin";

    // ---- 公共客户端（App Links，无密钥）----
    public const string AsstMobile = "asst-mobile";

    // ---- 平台机密客户端（内省/换发、服务间令牌；scope 资源与受众锚点）----
    public const string AsstServer = "asst-server";
    public const string FleetApi = "fleet-api";
    public const string MgmtApi = "mgmt-api";

    // ---- 宿主机操作命令注册（不经 DbSeeder；auth.appliket.com 专用实例）----
    public const string WebsiteAdmin = "pandalabs-website-admin";

    // ---- 演示客户端（DbSeeder 可选播种；同样受种子对账保护）----
    public const string DemoPublic = "demo-public";
    public const string DemoWeb = "demo-web";
    public const string DemoService = "demo-service";

    /// <summary>第一方 clientId 全集；新增播种/注册的第一方客户端必须在此登记。</summary>
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        MeWeb, AdminWeb, OasisWeb, FleetAdminWeb, AsstWeb, AsstAdmin,
        AsstMobile,
        AsstServer, FleetApi, MgmtApi,
        WebsiteAdmin,
        DemoPublic, DemoWeb, DemoService,
    };
}
