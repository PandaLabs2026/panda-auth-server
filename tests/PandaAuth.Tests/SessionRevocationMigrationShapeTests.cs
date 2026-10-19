using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SessionRevocationMigrationShapeTests
{
    [Fact]
    public void UpCreatesOnlyHashedSessionMarkersWithExpiryIndex()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        var table = Assert.Single(builder.Operations.OfType<CreateTableOperation>());
        Assert.Equal("panda_session_revocations", table.Name);
        Assert.Equal(["ClientId", "SessionIdHash"], table.PrimaryKey!.Columns);
        Assert.Equal(["ClientId", "ExpiresAt", "SessionIdHash"],
            table.Columns.Select(column => column.Name).OrderBy(name => name));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), index =>
            index.Table == table.Name && index.Columns.SequenceEqual(["ExpiresAt"]));
    }

    private sealed class TestMigration : AddSessionRevocations
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
