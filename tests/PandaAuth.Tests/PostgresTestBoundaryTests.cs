using Npgsql;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PostgresTestBoundaryTests
{
    [Theory]
    [InlineData("127.0.0.1", 43823, "postgres", false, true)]
    [InlineData("127.0.0.1", 5432, "panda_auth_quality_runner_0123456789abcdef", true, true)]
    [InlineData("127.0.0.1", 5432, "panda_auth_quality_runner_0123456789abcdef", false, false)]
    [InlineData("127.0.0.1", 5432, "postgres", true, false)]
    [InlineData("127.0.0.1", 5432, "panda_auth_quality_runner_bad", true, false)]
    [InlineData("localhost", 5432, "panda_auth_quality_runner_0123456789abcdef", true, false)]
    [InlineData("10.0.0.1", 43823, "postgres", false, false)]
    [InlineData("127.0.0.1", 5433, "panda_auth_quality_runner_0123456789abcdef", true, false)]
    public void Endpoint_RequiresExplicitSharedModeAndTaskRole(string host, int port, string user, bool shared, bool accepted)
    {
        var builder = new NpgsqlConnectionStringBuilder { Host = host, Port = port, Username = user };
        var error = Record.Exception(() => PostgresTestBoundary.ValidateEndpoint(builder, shared));
        if (accepted) Assert.Null(error);
        else Assert.IsType<InvalidOperationException>(error);
    }
}
