using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

public class SelfBuiltUserStoreMigrationShapeTests
{
    [Fact]
    public void UpCopiesLegacyIdentityData_WithoutDroppingLegacyTables()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        Assert.DoesNotContain(builder.Operations.OfType<DropTableOperation>(), operation =>
            operation.Name.StartsWith("AspNet", StringComparison.Ordinal));
        Assert.Contains(builder.Operations.OfType<SqlOperation>(), operation =>
            operation.Sql.Contains("INSERT INTO panda_users", StringComparison.Ordinal));
        Assert.Contains(builder.Operations.OfType<SqlOperation>(), operation =>
            operation.Sql.Contains("LOCK TABLE", StringComparison.Ordinal));
        Assert.Contains(builder.Operations.OfType<SqlOperation>(), operation =>
            operation.Sql.Contains("panda_auth_reject_legacy_identity_write", StringComparison.Ordinal));
    }

    private sealed class TestMigration : SelfBuiltUserStore
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
