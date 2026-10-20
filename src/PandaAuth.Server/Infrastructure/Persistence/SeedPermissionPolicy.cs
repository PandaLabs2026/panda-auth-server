using PandaAuth.Server.Configuration;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Persistence;

internal sealed record SeedPermissionChange(string[] Added, string[] Removed, string[] Target);

internal static class SeedPermissionPolicy
{
    internal static void Validate(SeedOptions options)
    {
        if (!Enum.IsDefined(options.PermissionReconciliationMode))
            throw new InvalidOperationException("Auth:Seed:PermissionReconciliationMode is invalid.");
        var enabled = new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            [FirstPartyClients.MeWeb] = options.Me.Enabled,
            [FirstPartyClients.AdminWeb] = options.AdminWeb.Enabled,
            [FirstPartyClients.OasisWeb] = options.OasisWeb.Enabled,
            [FirstPartyClients.FleetAdminWeb] = options.FleetAdminWeb.Enabled,
            [FirstPartyClients.CloudConsoleWeb] = options.CloudConsoleWeb.Enabled,
            [FirstPartyClients.AsstWeb] = options.AsstWeb.Enabled,
            [FirstPartyClients.AsstAdmin] = options.AsstAdmin.Enabled,
            [FirstPartyClients.AsstMobile] = options.AsstMobile.Enabled,
            [FirstPartyClients.AsstServer] = options.AsstServer.Enabled,
            [FirstPartyClients.FleetApi] = options.Fleet.Enabled,
            [FirstPartyClients.MgmtApi] = options.Mgmt.Enabled,
            [PandaAuthSessionApi.AdminClientId] = options.SessionState.Enabled,
            [PandaAuthSessionApi.MeClientId] = options.SessionState.Enabled,
            [FirstPartyClients.DemoPublic] = options.Demo.Enabled,
            [FirstPartyClients.DemoWeb] = options.Demo.Enabled,
            [FirstPartyClients.DemoService] = options.Demo.Enabled,
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (options.ExactPermissionClientIds is null)
            throw new InvalidOperationException("Auth:Seed:ExactPermissionClientIds must be an array.");
        foreach (var id in options.ExactPermissionClientIds)
            if (!options.Enabled || string.IsNullOrWhiteSpace(id) || !seen.Add(id) ||
                !enabled.TryGetValue(id, out var active) || !active)
                throw new InvalidOperationException("Auth:Seed:ExactPermissionClientIds must name unique enabled seeded clients.");
    }

    internal static SeedPermissionChange Plan(IEnumerable<string> current, IEnumerable<string> expected, SeedOptions options, string clientId)
    {
        var existing = current.ToHashSet(StringComparer.Ordinal);
        var desired = expected.ToHashSet(StringComparer.Ordinal);
        var exact = options.PermissionReconciliationMode == SeedPermissionReconciliationMode.Exact &&
            options.ExactPermissionClientIds.Contains(clientId, StringComparer.Ordinal);
        return new(desired.Except(existing).Order(StringComparer.Ordinal).ToArray(),
            exact ? existing.Except(desired).Order(StringComparer.Ordinal).ToArray() : [],
            (exact ? desired : existing.Union(desired)).Order(StringComparer.Ordinal).ToArray());
    }
}
