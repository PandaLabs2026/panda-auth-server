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
    public long RouteRevision { get; set; } = 1;
    public TenantRouteState State { get; set; } = TenantRouteState.Ready;
}
