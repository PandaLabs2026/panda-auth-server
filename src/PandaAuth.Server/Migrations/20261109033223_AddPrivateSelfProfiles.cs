using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddPrivateSelfProfiles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "panda_user_profiles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    Biography = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    ContactEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ContactEmailState = table.Column<int>(type: "integer", nullable: false),
                    Revision = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_user_profiles", x => x.UserId);
                    table.CheckConstraint("CK_profile_contact_state", "(\"ContactEmailState\" = 0 AND \"ContactEmail\" IS NULL) OR (\"ContactEmailState\" IN (1, 2) AND \"ContactEmail\" IS NOT NULL)");
                    table.CheckConstraint("CK_profile_revision", "\"Revision\" ~ '^[a-f0-9]{32}$'");
                    table.ForeignKey(
                        name: "FK_panda_user_profiles_panda_users_UserId",
                        column: x => x.UserId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "panda_profile_avatars",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    Bytes = table.Column<byte[]>(type: "bytea", nullable: false),
                    Width = table.Column<int>(type: "integer", nullable: false),
                    Height = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_profile_avatars", x => x.UserId);
                    table.CheckConstraint("CK_profile_avatar_bytes", "octet_length(\"Bytes\") BETWEEN 1 AND 262144");
                    table.CheckConstraint("CK_profile_avatar_dimensions", "\"Width\" BETWEEN 1 AND 512 AND \"Height\" BETWEEN 1 AND 512");
                    table.ForeignKey(
                        name: "FK_panda_profile_avatars_panda_user_profiles_UserId",
                        column: x => x.UserId,
                        principalTable: "panda_user_profiles",
                        principalColumn: "UserId",
                        onDelete: ReferentialAction.Cascade);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "panda_profile_avatars");

            migrationBuilder.DropTable(
                name: "panda_user_profiles");
        }
    }
}
