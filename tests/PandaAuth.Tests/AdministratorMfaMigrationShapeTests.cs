using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

public class AdministratorMfaMigrationShapeTests
{
    [Fact]
    public void Up_AddsOnlyMfaTables_AndDoesNotDropIdentityObservationTables()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        Assert.Contains(builder.Operations.OfType<CreateTableOperation>(), operation =>
            operation.Name == "panda_webauthn_credentials");
        Assert.Contains(builder.Operations.OfType<CreateTableOperation>(), operation =>
            operation.Name == "panda_totp_factors");
        Assert.Contains(builder.Operations.OfType<CreateTableOperation>(), operation =>
            operation.Name == "panda_mfa_recovery_events");
        Assert.DoesNotContain(builder.Operations.OfType<DropTableOperation>(), operation =>
            operation.Name.StartsWith("AspNet", StringComparison.Ordinal));
    }

    [Fact]
    public void DropWebAuthnCredentials_DropsRetiredTableOnly()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestDropMigration().BuildUp(builder);

        var drop = Assert.Single(builder.Operations.OfType<DropTableOperation>());
        Assert.Equal("panda_webauthn_credentials", drop.Name);
    }

    private sealed class TestDropMigration : DropWebAuthnCredentials
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }

    private sealed class TestMigration : AddAdministratorMfa
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
