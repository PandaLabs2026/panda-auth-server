using System.Text.RegularExpressions;
using Npgsql;

namespace PandaAuth.Tests;

internal static class PostgresTestBoundary
{
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
