using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class OnlineSigningKeyLifecycle : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "SigningEndsAt",
                table: "signing_keys",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "SigningStartsAt",
                table: "signing_keys",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "VerifyUntil",
                table: "signing_keys",
                type: "timestamp with time zone",
                nullable: true);

            // Existing binaries must be stopped before this migration. Legacy signing keys
            // are verification-only, including old retired rows that may protect live refresh tickets.
            migrationBuilder.Sql("""
                UPDATE signing_keys
                SET "VerifyUntil" = GREATEST("NotAfter", CURRENT_TIMESTAMP + INTERVAL '14 days 5 minutes')
                WHERE "Use" = 'sig';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SigningEndsAt",
                table: "signing_keys");

            migrationBuilder.DropColumn(
                name: "SigningStartsAt",
                table: "signing_keys");

            migrationBuilder.DropColumn(
                name: "VerifyUntil",
                table: "signing_keys");
        }
    }
}
