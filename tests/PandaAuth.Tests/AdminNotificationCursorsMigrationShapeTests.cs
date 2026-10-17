using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using PandaAuth.Server.Migrations;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 通知游标表迁移形状锁线：纯新增表（不动任何既有表），PK=AdminUserId。
/// </summary>
public class AdminNotificationCursorsMigrationShapeTests
{
    [Fact]
    public void UpAddsOnlyCursorTable_WithAdminUserIdPrimaryKey()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestMigration().BuildUp(builder);

        var tables = builder.Operations.OfType<CreateTableOperation>().ToList();
        Assert.Equal(["admin_notification_cursors"], tables.Select(table => table.Name));

        var table = Assert.Single(tables);
        Assert.Equal(["AdminUserId"], table.PrimaryKey!.Columns);
        Assert.Contains(table.Columns, column => column.Name == "LastAuditId" && columnClrTypeIsLong(column));
        Assert.Contains(table.Columns, column => column.Name == "UpdatedAt");

        // 纯新增：不出现任何对既有表的 ALTER/DROP/索引变更。
        Assert.DoesNotContain(builder.Operations, operation =>
            operation is not CreateTableOperation);
    }

    private static bool columnClrTypeIsLong(AddColumnOperation column) => column.ClrType == typeof(long);

    private class TestMigration : AddAdminNotificationCursors
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }
}
