using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddAdministratorMfa : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "panda_mfa_recovery_events",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    ActorUserId = table.Column<string>(type: "text", nullable: false),
                    TargetUserId = table.Column<string>(type: "text", nullable: false),
                    Reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    AuthenticationMethod = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RequestId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_mfa_recovery_events", x => x.Id);
                    table.ForeignKey(
                        name: "FK_panda_mfa_recovery_events_panda_users_ActorUserId",
                        column: x => x.ActorUserId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_panda_mfa_recovery_events_panda_users_TargetUserId",
                        column: x => x.TargetUserId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "panda_totp_factors",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    KeyVersion = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Nonce = table.Column<byte[]>(type: "bytea", nullable: false),
                    Ciphertext = table.Column<byte[]>(type: "bytea", nullable: false),
                    Tag = table.Column<byte[]>(type: "bytea", nullable: false),
                    LastAcceptedTimeStep = table.Column<long>(type: "bigint", nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConfirmedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_totp_factors", x => x.Id);
                    table.ForeignKey(
                        name: "FK_panda_totp_factors_panda_users_UserId",
                        column: x => x.UserId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "panda_webauthn_credentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    CredentialId = table.Column<byte[]>(type: "bytea", nullable: false),
                    PublicKeyCose = table.Column<byte[]>(type: "bytea", nullable: false),
                    SignatureCounter = table.Column<long>(type: "bigint", nullable: false),
                    Aaguid = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: true),
                    TransportsJson = table.Column<string>(type: "text", nullable: true),
                    BackupEligible = table.Column<bool>(type: "boolean", nullable: false),
                    BackupState = table.Column<bool>(type: "boolean", nullable: false),
                    FriendlyName = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
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
                name: "IX_panda_mfa_recovery_events_ActorUserId_CreatedAt",
                table: "panda_mfa_recovery_events",
                columns: new[] { "ActorUserId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_panda_mfa_recovery_events_TargetUserId_CreatedAt",
                table: "panda_mfa_recovery_events",
                columns: new[] { "TargetUserId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_panda_totp_factors_UserId",
                table: "panda_totp_factors",
                column: "UserId",
                unique: true,
                filter: "\"RevokedAt\" IS NULL");

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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "panda_mfa_recovery_events");

            migrationBuilder.DropTable(
                name: "panda_totp_factors");

            migrationBuilder.DropTable(
                name: "panda_webauthn_credentials");
        }
    }
}
