using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

public class MfaChallengeMigrationShapeTests
{
    [Fact]
    public void UpAddsOnlySelfOwnedChallengeTable_WithExpiryIndex()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        var tables = builder.Operations.OfType<CreateTableOperation>().ToList();
        Assert.Equal(["panda_mfa_challenges"], tables.Select(table => table.Name));
        Assert.DoesNotContain(builder.Operations, operation =>
            OperationName(operation).StartsWith("AspNet", StringComparison.Ordinal));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), index =>
            index.Table == "panda_mfa_challenges" && index.Columns.SequenceEqual(["ExpiresAt"]));
    }

    private static string OperationName(MigrationOperation operation) => operation switch
    {
        CreateTableOperation table => table.Name,
        AddColumnOperation column => column.Table,
        AlterColumnOperation column => column.Table,
        DropColumnOperation column => column.Table,
        DropTableOperation table => table.Name,
        CreateIndexOperation index => index.Table,
        _ => string.Empty,
    };

    private sealed class TestMigration : AddMfaChallenges
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
