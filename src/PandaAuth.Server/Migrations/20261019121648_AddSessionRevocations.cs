using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionRevocations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "panda_session_revocations",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SessionIdHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_session_revocations", x => new { x.ClientId, x.SessionIdHash });
                });

            migrationBuilder.CreateIndex(
                name: "IX_panda_session_revocations_ExpiresAt",
                table: "panda_session_revocations",
                column: "ExpiresAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "panda_session_revocations");
        }
    }
}
