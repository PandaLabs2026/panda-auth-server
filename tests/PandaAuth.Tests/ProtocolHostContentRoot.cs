using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;

namespace PandaAuth.Tests;

// WAF host bootstrap must contain only normal hosting settings. Early startup reads this
// private synthetic appsettings file through the standard contentRoot provider, before Build.
internal sealed class ProtocolHostContentRoot : IDisposable
{
    internal string Path { get; }
    internal ProtocolHostContentRoot(string connection, IReadOnlyDictionary<string, string> settings)
    {
        var parsed = new NpgsqlConnectionStringBuilder(connection);
        if (parsed.Host is not ("127.0.0.1" or "localhost") || parsed.Database is null ||
            !Regex.IsMatch(parsed.Database, "^panda_(auth_registration_test|auth_portal_test|protocol_test|mgmt_e2e)_[0-9a-f]{32}$"))
            throw new InvalidOperationException("Protocol content root requires an owned local test database.");
        var baseline = System.IO.Path.GetFullPath("../../../../../src/PandaAuth.Server/appsettings.json", AppContext.BaseDirectory);
        var json = JsonNode.Parse(File.ReadAllText(baseline))!.AsObject();
        var values = new Dictionary<string, string>(settings) { ["ConnectionStrings:Default"] = connection };
        foreach (var pair in values)
        {
            var keys = pair.Key.Split(':'); JsonObject parent = json;
            foreach (var key in keys[..^1])
            { if (parent[key] is not JsonObject child) parent[key] = child = new JsonObject(); parent = child; }
            parent[keys[^1]] = pair.Value;
        }
        Path = Directory.CreateTempSubdirectory("panda-auth-t0a2-protocol-").FullName;
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Directory.CreateDirectory(System.IO.Path.Combine(Path, "wwwroot", "brand"));
        var file = System.IO.Path.Combine(Path, "appsettings.json");
        File.WriteAllText(file, json.ToJsonString());
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
}
