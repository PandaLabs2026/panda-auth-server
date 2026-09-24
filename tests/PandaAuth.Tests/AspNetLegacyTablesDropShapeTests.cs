using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

public class AspNetLegacyTablesDropShapeTests
{
    private static readonly string[] LegacyTables =
    [
        "AspNetUsers", "AspNetRoles", "AspNetUserRoles", "AspNetUserClaims",
        "AspNetRoleClaims", "AspNetUserLogins", "AspNetUserTokens",
    ];

    [Fact]
    public void Up_DropsExactlyTheSevenLegacyTables_AndTheirReadOnlyTriggers()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        var sqlOperations = builder.Operations.OfType<SqlOperation>().ToList();
        var commandText = string.Join("\n", sqlOperations.Select(operation => operation.Sql));

        foreach (var table in LegacyTables)
        {
            Assert.Contains($"DROP TABLE IF EXISTS \"{table}\" CASCADE", commandText, StringComparison.Ordinal);
            Assert.Contains($"DROP TRIGGER IF EXISTS panda_auth_legacy_identity_read_only ON \"{table}\"", commandText, StringComparison.Ordinal);
        }

        // 触发器清理在删表之前。
        var triggerPosition = commandText.IndexOf("DROP TRIGGER", StringComparison.Ordinal);
        var tablePosition = commandText.IndexOf("DROP TABLE", StringComparison.Ordinal);
        Assert.True(triggerPosition >= 0 && tablePosition > triggerPosition);

        // 不触碰任何自有表 / OpenIddict 表：DROP TABLE 目标必须恰好是 7 张 AspNet 表。
        var dropTargets = System.Text.RegularExpressions.Regex
            .Matches(commandText, @"DROP TABLE IF EXISTS ""(?<name>[^""]+)""")
            .Select(match => match.Groups["name"].Value)
            .ToList();
        Assert.Equal(
            LegacyTables.OrderBy(name => name, StringComparer.Ordinal).ToList(),
            dropTargets.OrderBy(name => name, StringComparer.Ordinal).ToList());
        Assert.DoesNotContain("__EFMigrationsHistory", commandText, StringComparison.Ordinal);
        Assert.Empty(builder.Operations.OfType<CreateTableOperation>());
        Assert.Empty(builder.Operations.OfType<DropTableOperation>());
    }

    [Fact]
    public void Up_CoversEveryLegacyTableFromBackupInventory()
    {
        // 2026-09-23 备份实测的旧表清单必须全部覆盖，防清单漂移。
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        var commandText = string.Join("\n", builder.Operations.OfType<SqlOperation>().Select(operation => operation.Sql));
        var dropped = LegacyTables.Where(table => commandText.Contains($"DROP TABLE IF EXISTS \"{table}\"", StringComparison.Ordinal)).ToList();
        Assert.Equal(LegacyTables.Length, dropped.Count);
    }

    private sealed class TestMigration : AspNetLegacyTablesDrop
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
