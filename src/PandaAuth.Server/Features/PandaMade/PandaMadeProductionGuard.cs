using System.Text.Json;
using Npgsql;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.PandaMade;

internal static class PandaMadeProductionGuard
{
    internal static NpgsqlConnectionStringBuilder ValidateConfiguration(IConfiguration config, string operation)
    {
        var role = operation switch {
            "register" => "pandamade_auth_operator", "migrate" => "pandamade_auth_migrator",
            _ => throw new InvalidOperationException()
        };
        var connection = new NpgsqlConnectionStringBuilder(config.GetConnectionString("PandaMadeOperations"));
        if (config["PandaMade:Target"] != "pandamade-production" || config["Auth:Issuer"] != PandaMadeScopes.Issuer ||
            config["Auth:PandaMade:AdminOrigin"] != "https://admin.pandamade.net/" ||
            connection.Host != "pandalabs-postgres" || connection.Port != 5432 || connection.Database != "pandamade_auth" ||
            connection.Username != role || string.IsNullOrWhiteSpace(connection.Password)) throw new InvalidOperationException();
        connection.Timeout = 5;
        return connection;
    }

    internal static async Task<string> RequireAsync(IConfiguration config, string operation)
    {
        var connection = ValidateConfiguration(config, operation);
        if (!OperatingSystem.IsLinux() || Environment.UserName == "root") throw new InvalidOperationException();
        const string marker = "/run/pandamade/machine.json";
        var file = new FileInfo(marker);
        if (!file.Exists || file.LinkTarget is not null ||
            (File.GetUnixFileMode(marker) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new InvalidOperationException();
        using var identity = JsonDocument.Parse(await File.ReadAllTextAsync(marker));
        if (identity.RootElement.GetProperty("machine_id").GetString() != "tcloud-sg-01") throw new InvalidOperationException();
        await using var db = new NpgsqlConnection(connection.ConnectionString);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT current_database(), current_user, session_user, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user", db);
        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync() || reader.GetString(0) != "pandamade_auth" || reader.GetString(1) != connection.Username ||
            reader.GetString(2) != connection.Username || reader.GetBoolean(3) || reader.GetBoolean(4) || reader.GetBoolean(5) || reader.GetBoolean(6) || reader.GetBoolean(7)) throw new InvalidOperationException();
        return connection.ConnectionString;
    }
}
