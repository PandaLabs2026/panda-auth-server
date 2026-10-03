using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.PortalClients;

internal sealed class PortalClientClosedException(string code) : Exception(code);

internal sealed record PortalClientRequest(JsonElement Json, string Digest, bool Unregister)
{
    internal const string Kind = "legacy-t0000-portal";
    internal const string Issuer = "https://t0000-auth.s001.pandalabs.cn/";
    internal const string Callback = "https://t0000.s001.pandalabs.cn/callback";
    internal const string LogoutCallback = "https://t0000.s001.pandalabs.cn/callback/logout";
    internal const string Executor = "jiayuhu@tcloud-sh-01";
    internal static readonly string[] PermissionsSet = [Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
        Permissions.Endpoints.EndSession, Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code, Permissions.Scopes.Profile];
    internal static readonly string[] RequirementsSet = [Requirements.Features.ProofKeyForCodeExchange];
    internal string this[string key] => Json.GetProperty(key).GetString()!;
    internal string OperationId => this["operationId"];
    internal string? ClientId => Json.TryGetProperty("clientId", out var value) ? value.GetString() : null;
    internal bool InWindow(DateTimeOffset now) => Utc(this["maintenanceStartUtc"]) <= now && now <= Utc(this["maintenanceEndUtc"]);

    internal static void Require(bool condition, string code = "invalid-request")
    { if (!condition) throw new PortalClientClosedException(code); }
    internal static DateTimeOffset Utc(string value)
    {
        Require(Regex.IsMatch(value, @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z", RegexOptions.CultureInvariant));
        Require(DateTimeOffset.TryParseExact(value, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var result));
        return result;
    }
    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static string Timestamp(DateTimeOffset now) => now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
    internal static JsonElement ClosedJson(byte[] raw)
    {
        Require(raw.Length is > 0 and <= 32768);
        using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 8 });
        CheckDuplicates(document.RootElement);
        return document.RootElement.Clone();
    }
    private static void CheckDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject()) { Require(keys.Add(property.Name)); CheckDuplicates(property.Value); }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var value in element.EnumerateArray()) CheckDuplicates(value);
    }
    internal static PortalClientRequest Parse(byte[] raw, bool unregister, DateTimeOffset now)
    {
        var json = ClosedJson(raw);
        Require(json.ValueKind == JsonValueKind.Object);
        string[] common = ["schemaVersion", "deploymentKind", "tenantId", "zone", "machineId", "operationId",
            "authMetaSource", "authServerSource", "planReference", "executionReference", "executor",
            "maintenanceStartUtc", "maintenanceEndUtc", "validUntilUtc"];
        var required = common.Concat(unregister ? ["clientId", "requestDigest", "registrationDigest"] : ["issuer", "redirectUri", "postLogoutRedirectUri"]).ToHashSet(StringComparer.Ordinal);
        var keys = json.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        Require(required.IsSubsetOf(keys) && keys.All(k => required.Contains(k) || !unregister && k == "clientId"));
        Require(json.GetProperty("schemaVersion").GetRawText() == "1");
        foreach (var property in json.EnumerateObject().Where(p => p.Name != "schemaVersion"))
        {
            Require(property.Value.ValueKind == JsonValueKind.String);
            Require(!property.Value.GetString()!.Any(char.IsControl));
        }
        var request = new PortalClientRequest(json, Hash(raw), unregister);
        Require(request["deploymentKind"] == Kind && request["tenantId"] == "t0000" && request["zone"] == "s001" && request["machineId"] == "tcloud-sh-01");
        Require(Guid.TryParseExact(request.OperationId, "D", out var operation) && operation != Guid.Empty && operation.ToString("D") == request.OperationId);
        Require(request["executor"] == Executor);
        foreach (var name in new[] { "authMetaSource", "authServerSource" })
            Require(Regex.IsMatch(request[name], @"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant) && request[name].Any(c => c != '0'));
        foreach (var name in new[] { "planReference", "executionReference" }) Require(Regex.IsMatch(request[name], @"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\z", RegexOptions.CultureInvariant));
        if (request.ClientId is { } id) Require(Regex.IsMatch(id, @"\A[A-Za-z0-9][A-Za-z0-9._-]{2,63}\z", RegexOptions.CultureInvariant));
        var start = Utc(request["maintenanceStartUtc"]); var end = Utc(request["maintenanceEndUtc"]); var valid = Utc(request["validUntilUtc"]);
        Require(start < end && end <= valid && end - start <= TimeSpan.FromDays(1) && valid - start <= TimeSpan.FromDays(90) && now <= valid, "expired-request");
        if (unregister)
            foreach (var name in new[] { "requestDigest", "registrationDigest" }) Require(Regex.IsMatch(request[name], @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant));
        else Require(request["issuer"] == Issuer && request["redirectUri"] == Callback && request["postLogoutRedirectUri"] == LogoutCallback);
        return request;
    }

    internal static OpenIddictApplicationDescriptor Descriptor(string clientId)
    {
        var descriptor = new OpenIddictApplicationDescriptor { ClientId = clientId, ClientType = ClientTypes.Public, ConsentType = ConsentTypes.Implicit };
        descriptor.RedirectUris.Add(new Uri(Callback)); descriptor.PostLogoutRedirectUris.Add(new Uri(LogoutCallback));
        descriptor.Permissions.UnionWith(PermissionsSet); descriptor.Requirements.UnionWith(RequirementsSet);
        return descriptor;
    }
    internal static byte[] RegistrationBytes(OpenIddictApplicationDescriptor descriptor)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output))
        {
            writer.WriteStartObject();
            writer.WriteString("clientId", descriptor.ClientId); writer.WriteString("clientType", descriptor.ClientType);
            writer.WriteString("consentType", descriptor.ConsentType); writer.WriteString("issuer", Issuer);
            WriteArray(writer, "redirectUris", descriptor.RedirectUris.Select(u => u.AbsoluteUri));
            WriteArray(writer, "postLogoutRedirectUris", descriptor.PostLogoutRedirectUris.Select(u => u.AbsoluteUri));
            WriteArray(writer, "permissions", descriptor.Permissions); WriteArray(writer, "requirements", descriptor.Requirements);
            writer.WriteEndObject();
        }
        return output.ToArray();
    }
    private static void WriteArray(Utf8JsonWriter writer, string name, IEnumerable<string> values)
    {
        writer.WriteStartArray(name);
        foreach (var value in values.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }
    internal static string RegistrationDigest(OpenIddictApplicationDescriptor descriptor) => Hash(RegistrationBytes(descriptor));
    internal static string Receipt(PortalClientRequest request, OpenIddictApplicationDescriptor descriptor, string result, DateTimeOffset now)
    {
        var values = new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1, ["deploymentKind"] = Kind, ["tenantId"] = "t0000", ["zone"] = "s001", ["machineId"] = "tcloud-sh-01",
            ["operationId"] = request.OperationId, ["requestDigest"] = request.Digest, ["clientId"] = descriptor.ClientId,
            ["result"] = result, ["clientType"] = descriptor.ClientType, ["consentType"] = descriptor.ConsentType, ["issuer"] = Issuer,
            ["redirectUris"] = new[] { Callback }, ["postLogoutRedirectUris"] = new[] { LogoutCallback },
            ["permissions"] = PermissionsSet.Order(StringComparer.Ordinal).ToArray(), ["requirements"] = RequirementsSet,
            ["registrationDigest"] = RegistrationDigest(descriptor), ["authMetaSource"] = request["authMetaSource"], ["authServerSource"] = request["authServerSource"],
            ["planReference"] = request["planReference"], ["executionReference"] = request["executionReference"], ["executor"] = Executor, ["observedUtc"] = Timestamp(now),
        };
        return JsonSerializer.Serialize(values) + "\n";
    }
}
