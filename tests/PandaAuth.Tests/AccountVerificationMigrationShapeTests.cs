using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

public class AccountVerificationMigrationShapeTests
{
    [Fact]
    public void UpAddsOnlySelfOwnedVerificationTables_WithUniqueAndExpiryIndexes()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        var tables = builder.Operations.OfType<CreateTableOperation>().ToList();
        Assert.Equal(["panda_email_verifications", "panda_password_reset_requests"],
            tables.Select(table => table.Name).OrderBy(name => name));
        Assert.DoesNotContain(builder.Operations, operation =>
            OperationName(operation).StartsWith("AspNet", StringComparison.Ordinal));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), index =>
            index.Table == "panda_email_verifications" && index.IsUnique &&
            index.Columns.SequenceEqual(["TokenHash"]));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), index =>
            index.Table == "panda_password_reset_requests" && index.IsUnique &&
            index.Columns.SequenceEqual(["TokenHash"]));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), index =>
            index.Table == "panda_email_verifications" && index.Columns.SequenceEqual(["ExpiresAt"]));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), index =>
            index.Table == "panda_password_reset_requests" && index.Columns.SequenceEqual(["ExpiresAt"]));
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

    private sealed class TestMigration : AddAccountVerificationAndPasswordReset
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
