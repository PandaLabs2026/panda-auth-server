using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddProfileContactChallenges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "panda_profile_contact_challenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    Address = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TokenDigest = table.Column<byte[]>(type: "bytea", nullable: false),
                    ExpectedRevision = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    DeliveryId = table.Column<Guid>(type: "uuid", nullable: false),
                    State = table.Column<int>(type: "integer", nullable: false),
                    FailedAttempts = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_profile_contact_challenges", x => x.Id);
                    table.CheckConstraint("CK_profile_challenge_attempts", "\"FailedAttempts\" BETWEEN 0 AND 5");
                    table.CheckConstraint("CK_profile_challenge_digest", "octet_length(\"TokenDigest\") = 32");
                    table.CheckConstraint("CK_profile_challenge_state", "\"State\" BETWEEN 0 AND 5");
                    table.ForeignKey(
                        name: "FK_panda_profile_contact_challenges_panda_user_profiles_UserId",
                        column: x => x.UserId,
                        principalTable: "panda_user_profiles",
                        principalColumn: "UserId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "panda_profile_rate_limits",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    CreationWindowStart = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CreationCount = table.Column<int>(type: "integer", nullable: false),
                    LastChallengeAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ConfirmationWindowStart = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ConfirmationCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_profile_rate_limits", x => x.UserId);
                    table.CheckConstraint("CK_profile_confirmation_count", "\"ConfirmationCount\" BETWEEN 0 AND 10");
                    table.CheckConstraint("CK_profile_creation_count", "\"CreationCount\" BETWEEN 0 AND 5");
                    table.ForeignKey(
                        name: "FK_panda_profile_rate_limits_panda_users_UserId",
                        column: x => x.UserId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_panda_profile_contact_challenges_DeliveryId",
                table: "panda_profile_contact_challenges",
                column: "DeliveryId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_panda_profile_contact_challenges_ExpiresAt",
                table: "panda_profile_contact_challenges",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_panda_profile_contact_challenges_UserId",
                table: "panda_profile_contact_challenges",
                column: "UserId",
                unique: true,
                filter: "\"State\" IN (0, 1)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "panda_profile_contact_challenges");

            migrationBuilder.DropTable(
                name: "panda_profile_rate_limits");
        }
    }
}
