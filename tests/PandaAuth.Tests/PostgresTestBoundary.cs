using System.Text.RegularExpressions;
using Npgsql;

namespace PandaAuth.Tests;

internal static class PostgresTestBoundary
{
    internal static async Task DropOwnedDatabaseAsync(string connectionString, string prefix)
    {
        var endpoint = new NpgsqlConnectionStringBuilder(connectionString);
        ValidateEndpoint(endpoint, SharedMode);
        var database = endpoint.Database;
        if (!Regex.IsMatch(database ?? "", "^" + Regex.Escape(prefix) + "[0-9a-f]{32}$", RegexOptions.CultureInvariant))
            throw new InvalidOperationException("Refusing cleanup outside the task-owned database namespace.");
        NpgsqlConnection.ClearPool(new NpgsqlConnection(connectionString));
        endpoint.Database = "postgres";
        await using var admin = new NpgsqlConnection(endpoint.ConnectionString);
        await admin.OpenAsync();
        await using var ownership = new NpgsqlCommand("SELECT pg_get_userbyid(datdba) = current_user FROM pg_database WHERE datname = $1", admin);
        ownership.Parameters.AddWithValue(database!);
        if (await ownership.ExecuteScalarAsync() is not true)
            throw new InvalidOperationException("Task role must own the database being removed.");
        // Native FORCE handles autovacuum workers. EF's pg_terminate_backend loop requires
        // excessive privileges when such a worker belongs to the cluster administrator.
        await using var drop = new NpgsqlCommand($"DROP DATABASE \"{database}\" WITH (FORCE)", admin);
        await drop.ExecuteNonQueryAsync();
    }

    internal static bool SharedMode => Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_SHARED_POSTGRES") == "1";

    internal static void ValidateEndpoint(NpgsqlConnectionStringBuilder connection, bool shared)
    {
        var disposable = connection.Port == 43823;
        var approvedShared = shared && connection.Port == 5432 && connection.Username is not null &&
            Regex.IsMatch(connection.Username, "^panda_auth_quality_runner_[0-9a-f]{16}$", RegexOptions.CultureInvariant);
        if (connection.Host != "127.0.0.1" || (!disposable && !approvedShared))
            throw new InvalidOperationException("PostgreSQL tests require an isolated loopback endpoint or explicitly approved shared mode with a task-owned test role.");
    }
}
