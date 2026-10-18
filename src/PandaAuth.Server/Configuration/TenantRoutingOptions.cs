using PandaAuth.Shared;

namespace PandaAuth.Server.Configuration;

public sealed class TenantRoutingOptions
{
    /// <summary>
    /// 租户主机路由总开关。默认关闭：既有单租户部署（无 bindings）行为不变；
    /// 启用时规范主机必须能在 bindings 中解析，否则请求 fail-closed（421），不静默放行。
    /// </summary>
    public bool Enabled { get; set; }

    public TenantRouteBindingOptions[] Bindings { get; set; } = [];
}

public sealed class TenantRouteBindingOptions
{
    public string TenantId { get; set; } = string.Empty;
    public TenantProduct Product { get; set; }

    /// <summary>服务器分区（拓扑 v2：sNNN）。默认 s001 兼容既有 env 注入；多分区部署必须显式配置。</summary>
    public string Zone { get; set; } = "s001";
    public long RouteRevision { get; set; } = 1;
    public TenantRouteState State { get; set; } = TenantRouteState.Ready;
}
