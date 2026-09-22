using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ClaimsAndExternalIdentityMigrationShapeTests
{
    [Fact]
    public void ClaimsMigration_AddsOnlySelfOwnedClaimTables()
    {
        var builder = new MigrationBuilder("Npgsql");

        new ClaimsMigration().BuildUp(builder);

        Assert.Equal(
            ["panda_role_claims", "panda_user_claims"],
            builder.Operations.OfType<CreateTableOperation>()
                .Select(operation => operation.Name).OrderBy(name => name));
        Assert.DoesNotContain(builder.Operations, operation =>
            OperationName(operation).StartsWith("AspNet", StringComparison.Ordinal) ||
            OperationName(operation).StartsWith("openiddict", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), operation =>
            operation.Table == "panda_user_claims" && operation.IsUnique &&
            operation.Columns.SequenceEqual(["UserId", "ClaimType", "ClaimValue", "Scope"]));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), operation =>
            operation.Table == "panda_role_claims" && operation.IsUnique &&
            operation.Columns.SequenceEqual(["RoleId", "ClaimType", "ClaimValue", "Scope"]));
    }

    [Fact]
    public void ExternalIdentityMigration_UsesStableSubjectKeyAndStoresNoProviderToken()
    {
        var builder = new MigrationBuilder("Npgsql");

        new ExternalIdentityMigration().BuildUp(builder);

        var table = Assert.Single(builder.Operations.OfType<CreateTableOperation>(),
            operation => operation.Name == "panda_external_identities");
        Assert.Contains(table.Columns, column => column.Name == "Provider");
        Assert.Contains(table.Columns, column => column.Name == "ProviderSubject");
        Assert.DoesNotContain(table.Columns, column =>
            column.Name.Contains("token", StringComparison.OrdinalIgnoreCase) ||
            column.Name.Contains("secret", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(builder.Operations.OfType<CreateIndexOperation>(), operation =>
            operation.Table == "panda_external_identities" && operation.IsUnique &&
            operation.Columns.SequenceEqual(["Provider", "ProviderSubject"]));
        Assert.DoesNotContain(builder.Operations.OfType<DropTableOperation>(), operation =>
            operation.Name.StartsWith("AspNet", StringComparison.Ordinal));
    }

    private static string OperationName(MigrationOperation operation) => operation switch
    {
        CreateTableOperation table => table.Name,
        CreateIndexOperation index => index.Table,
        DropTableOperation table => table.Name,
        _ => string.Empty,
    };

    private sealed class ClaimsMigration : AddClaimsGovernance
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }

    private sealed class ExternalIdentityMigration : AddExternalIdentityLinks
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
