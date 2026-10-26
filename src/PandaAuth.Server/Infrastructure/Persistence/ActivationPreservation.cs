using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Persistence;

public sealed record ActivationDataState(Dictionary<string,string> Tables, bool AddAdminPermission, bool CreateAdminScope);

/// <summary>Cold activation invariants. No identities, private material or row contents leave this process.</summary>
public static class ActivationPreservation
{
    private static string Permission => OpenIddictConstants.Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope;
    private static void Require(bool condition)
    { if (!condition) throw new InvalidOperationException("activation_data_changed"); }
    private static JsonNode? Canonical(JsonNode? value) => value switch
    {
        JsonObject obj => new JsonObject(obj.OrderBy(pair=>pair.Key,StringComparer.Ordinal)
            .Select(pair=>new KeyValuePair<string,JsonNode?>(pair.Key,Canonical(pair.Value)))),
        JsonArray array => new JsonArray(array.Select(Canonical).ToArray()),
        _ => value?.DeepClone()
    };
    public static string Normalize(string table,string json,bool addAdminPermission)
    {
        var row=JsonNode.Parse(json)?.AsObject() ?? throw new InvalidOperationException("activation_data_changed");
        if(table=="signing_keys")
            foreach(var column in new[]{"SigningStartsAt","SigningEndsAt","VerifyUntil"}) row.Remove(column);
        if(table=="OpenIddictApplications" && addAdminPermission && row["ClientId"]?.GetValue<string>()==FirstPartyClients.AdminWeb)
        {
            var permissions=JsonSerializer.Deserialize<string[]>(row["Permissions"]?.GetValue<string>() ?? "[]") ?? [];
            row["Permissions"]=JsonSerializer.Serialize(permissions.Where(value=>value!=Permission).Order(StringComparer.Ordinal).ToArray());
            row.Remove("ConcurrencyToken");
        }
        return Canonical(row)!.ToJsonString();
    }

    public static async Task<ActivationDataState> CaptureAsync(string connectionString,ActivationDataState? original=null)
    {
        await using var connection=new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction=await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        await using(var readOnly=new NpgsqlCommand("SET TRANSACTION READ ONLY",connection,transaction)) await readOnly.ExecuteNonQueryAsync();
        var addPermission=original?.AddAdminPermission ?? false;
        var createScope=original?.CreateAdminScope ?? false;
        if(original is null)
        {
            await using var application=new NpgsqlCommand("SELECT NOT coalesce(\"Permissions\"::jsonb ? @permission,false) FROM \"OpenIddictApplications\" WHERE \"ClientId\"=@client",connection,transaction);
            application.Parameters.AddWithValue("permission",Permission);application.Parameters.AddWithValue("client",FirstPartyClients.AdminWeb);
            addPermission=(bool)(await application.ExecuteScalarAsync() ?? throw new InvalidOperationException("activation_data_changed"));
            await using var scope=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM \"OpenIddictScopes\" WHERE \"Name\"=@name)",connection,transaction);
            scope.Parameters.AddWithValue("name",PandaAuthAdminApi.Scope);createScope=(bool)(await scope.ExecuteScalarAsync())!;
        }
        var tables=new List<string>();
        await using(var command=new NpgsqlCommand("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename COLLATE \"C\"",connection,transaction))
        await using(var reader=await command.ExecuteReaderAsync())
            while(await reader.ReadAsync()) { Require(tables.Count<512);tables.Add(reader.GetString(0)); }
        Require(tables.Contains("__EFMigrationsHistory") && tables.Contains("signing_keys"));
        var result=new Dictionary<string,string>(StringComparer.Ordinal);long totalBytes=0;
        foreach(var table in tables)
        {
            var quoted="\""+table.Replace("\"","\"\"")+"\"";
            var hashes=new List<string>();
            await using var command=new NpgsqlCommand("SELECT CASE WHEN octet_length(to_jsonb(t)::text)<=2097152 THEN to_jsonb(t)::text ELSE NULL END FROM public."+quoted+" t",connection,transaction);
            await using var reader=await command.ExecuteReaderAsync();
            while(await reader.ReadAsync())
            {
                Require(!reader.IsDBNull(0));var json=reader.GetString(0);
                totalBytes+=Encoding.UTF8.GetByteCount(json);Require(totalBytes<=64*1024*1024);
                var row=JsonNode.Parse(json)!.AsObject();
                if(table=="__EFMigrationsHistory" && row["MigrationId"]?.GetValue<string>()==OperationalCommand.SigningMigration) continue;
                if(table=="OpenIddictScopes" && createScope && row["Name"]?.GetValue<string>()==PandaAuthAdminApi.Scope)
                {
                    var resources=JsonSerializer.Deserialize<string[]>(row["Resources"]?.GetValue<string>() ?? "[]") ?? [];
                    Require(resources.ToHashSet(StringComparer.Ordinal).SetEquals([PandaAuthAdminApi.Audience]));
                    continue;
                }
                hashes.Add(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(table,json,addPermission)))));
            }
            hashes.Sort(StringComparer.Ordinal);
            result.Add(table,Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(string.Concat(hashes)))));
        }
        await transaction.RollbackAsync();
        return new(result,addPermission,createScope);
    }

    public static void RequireUnchanged(ActivationDataState original,ActivationDataState after)
    {
        Require(original.Tables.Count==after.Tables.Count && original.Tables.All(pair=>after.Tables.TryGetValue(pair.Key,out var hash) && hash==pair.Value));
    }
}
