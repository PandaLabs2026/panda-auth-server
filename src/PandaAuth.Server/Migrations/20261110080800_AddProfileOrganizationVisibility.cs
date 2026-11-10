using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddProfileOrganizationVisibility : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "panda_profile_organization_visibility",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "character varying(450)", maxLength: 450, nullable: false),
                    OrganizationKey = table.Column<Guid>(type: "uuid", nullable: false),
                    Fields = table.Column<int>(type: "integer", nullable: false),
                    Revision = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_panda_profile_organization_visibility", x => new { x.UserId, x.OrganizationKey });
                    table.CheckConstraint("CK_profile_organization_fields", "\"Fields\" BETWEEN 0 AND 15");
                    table.CheckConstraint("CK_profile_organization_key", "\"OrganizationKey\" <> '00000000-0000-0000-0000-000000000000'::uuid");
                    table.CheckConstraint("CK_profile_organization_revision", "\"Revision\" ~ '^[a-f0-9]{32}$'");
                    table.ForeignKey(
                        name: "FK_panda_profile_organization_visibility_panda_users_UserId",
                        column: x => x.UserId,
                        principalTable: "panda_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "panda_profile_organization_visibility");
        }
    }
}
