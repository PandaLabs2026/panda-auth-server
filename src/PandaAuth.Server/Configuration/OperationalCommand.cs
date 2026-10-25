using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace PandaAuth.Server.Configuration;

public static class OperationalCommand
{
    public const string SigningMigration = "20261025074425_OnlineSigningKeyLifecycle";
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static bool IsRequested(string[] args) => args.Any(value => value is "--validate-config" or "--security-state");
    public static void Write(TextWriter writer, object report) => writer.WriteLine(JsonSerializer.Serialize(report, Json));

    public static async Task<int> RunAsync(string[] args, IConfiguration configuration, IHostEnvironment environment, TextWriter output)
    {
        if (args is ["--validate-config", "--mode", "runtime" or "migrate"])
        {
            var report = StartupConfiguration.Validate(configuration, environment, args[2] == "migrate");
            Write(output, report);
            return report.Valid ? 0 : 2;
        }
        if (args is ["--security-state"])
        {
            try
            {
                var settings = new NpgsqlConnectionStringBuilder(configuration.GetConnectionString("Migration"));
                if (string.IsNullOrWhiteSpace(settings.Host) || string.IsNullOrWhiteSpace(settings.Database) || string.IsNullOrWhiteSpace(settings.Username))
                    throw new InvalidOperationException();
                await using var connection = new NpgsqlConnection(settings.ConnectionString);
                await connection.OpenAsync();
                await using var transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead);
                await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction)) await readOnly.ExecuteNonQueryAsync();
                await using var query = new NpgsqlCommand("""
                    SELECT EXISTS (SELECT 1 FROM "__EFMigrationsHistory" WHERE "MigrationId" = $1),
                           (SELECT oid::text FROM pg_database WHERE datname = current_database()),
                           (SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public'
                            AND table_name = 'signing_keys' AND column_name IN ('SigningStartsAt', 'SigningEndsAt', 'VerifyUntil')
                            AND data_type = 'timestamp with time zone'),
                           to_regclass('public.signing_keys') IS NOT NULL
                    """, connection, transaction);
                query.Parameters.AddWithValue(SigningMigration);
                await using var reader = await query.ExecuteReaderAsync();
                if (!await reader.ReadAsync()) throw new InvalidOperationException();
                var upgraded = reader.GetBoolean(0);
                if (!reader.GetBoolean(3) || reader.GetInt64(2) != (upgraded ? 3L : 0L)) throw new InvalidOperationException();
                var fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
                    settings.Host.ToLowerInvariant() + "\0" + settings.Port + "\0" + settings.Database + "\0" + reader.GetString(1))));
                Write(output, new { Schema = 1, Valid = true, Compatibility = upgraded ? "online-signing-v1" : "legacy", DatabaseFingerprint = fingerprint });
                return 0;
            }
            catch (Exception exception) when (exception is NpgsqlException or InvalidOperationException or ArgumentException)
            {
                Write(output, new ConfigurationReport(1, false, [new("ConnectionStrings:Migration", "security_state_unknown")]));
                return 2;
            }
        }
        Write(output, new ConfigurationReport(1, false, [new("command", "command_invalid")]));
        return 2;
    }
}
