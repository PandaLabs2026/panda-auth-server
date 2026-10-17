using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddAdminNotificationCursors : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "admin_notification_cursors",
                columns: table => new
                {
                    AdminUserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    LastAuditId = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_admin_notification_cursors", x => x.AdminUserId);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "admin_notification_cursors");
        }
    }
}
