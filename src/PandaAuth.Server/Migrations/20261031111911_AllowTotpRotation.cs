using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AllowTotpRotation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_panda_totp_factors_UserId",
                table: "panda_totp_factors");

            migrationBuilder.CreateIndex(
                name: "IX_panda_totp_factors_UserId_Confirmed",
                table: "panda_totp_factors",
                column: "UserId",
                unique: true,
                filter: "\"RevokedAt\" IS NULL AND \"ConfirmedAt\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_panda_totp_factors_UserId_Pending",
                table: "panda_totp_factors",
                column: "UserId",
                unique: true,
                filter: "\"RevokedAt\" IS NULL AND \"ConfirmedAt\" IS NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_panda_totp_factors_UserId_Confirmed",
                table: "panda_totp_factors");

            migrationBuilder.DropIndex(
                name: "IX_panda_totp_factors_UserId_Pending",
                table: "panda_totp_factors");

            migrationBuilder.CreateIndex(
                name: "IX_panda_totp_factors_UserId",
                table: "panda_totp_factors",
                column: "UserId",
                unique: true,
                filter: "\"RevokedAt\" IS NULL");
        }
    }
}
