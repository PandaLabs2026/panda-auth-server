using PandaAuth.Shared;

namespace PandaAuth.Server.Configuration;

public sealed class TenantRoutingOptions
{
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
