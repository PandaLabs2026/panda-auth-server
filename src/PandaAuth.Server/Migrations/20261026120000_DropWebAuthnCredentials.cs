using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class DropWebAuthnCredentials : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "panda_webauthn_credentials");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "panda_webauthn_credentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Aaguid = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: false),
                    BackupEligible = table.Column<bool>(type: "boolean", nullable: false),
                    BackupState = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CredentialId = table.Column<byte[]>(type: "bytea", nullable: false),
                    FriendlyName = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    PublicKeyCose = table.Column<byte[]>(type: "bytea", nullable: false),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    SignatureCounter = table.Column<long>(type: "bigint", nullable: false),
                    TransportsJson = table.Column<string>(type: "text", nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_webauthn_credentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_panda_webauthn_credentials_panda_users_UserId",
                        column: x => x.UserId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_panda_webauthn_credentials_CredentialId",
                table: "panda_webauthn_credentials",
                column: "CredentialId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_panda_webauthn_credentials_UserId_RevokedAt",
                table: "panda_webauthn_credentials",
                columns: new[] { "UserId", "RevokedAt" });
        }
    }
}
