using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddAccountVerificationAndPasswordReset : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "panda_email_verifications",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    SubjectId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    NormalizedTarget = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsumedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Attempts = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_email_verifications", x => x.Id);
                    table.ForeignKey(
                        name: "FK_panda_email_verifications_panda_users_SubjectId",
                        column: x => x.SubjectId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "panda_password_reset_requests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    SubjectId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: true),
                    NormalizedTarget = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsumedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Attempts = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_password_reset_requests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_panda_password_reset_requests_panda_users_SubjectId",
                        column: x => x.SubjectId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_panda_email_verifications_ExpiresAt",
                table: "panda_email_verifications",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_panda_email_verifications_SubjectId_Purpose_NormalizedTarge~",
                table: "panda_email_verifications",
                columns: new[] { "SubjectId", "Purpose", "NormalizedTarget", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_panda_email_verifications_TokenHash",
                table: "panda_email_verifications",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_panda_password_reset_requests_ExpiresAt",
                table: "panda_password_reset_requests",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_panda_password_reset_requests_NormalizedTarget_Purpose_Crea~",
                table: "panda_password_reset_requests",
                columns: new[] { "NormalizedTarget", "Purpose", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_panda_password_reset_requests_SubjectId",
                table: "panda_password_reset_requests",
                column: "SubjectId");

            migrationBuilder.CreateIndex(
                name: "IX_panda_password_reset_requests_TokenHash",
                table: "panda_password_reset_requests",
                column: "TokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "panda_email_verifications");

            migrationBuilder.DropTable(
                name: "panda_password_reset_requests");
        }
    }
}
