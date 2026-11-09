using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class AddAvatarUploadLimits : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "AvatarCount",
                table: "panda_profile_rate_limits",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "AvatarWindowStart",
                table: "panda_profile_rate_limits",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "CK_profile_avatar_count",
                table: "panda_profile_rate_limits",
                sql: "\"AvatarCount\" BETWEEN 0 AND 2");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_profile_avatar_count",
                table: "panda_profile_rate_limits");

            migrationBuilder.DropColumn(
                name: "AvatarCount",
                table: "panda_profile_rate_limits");

            migrationBuilder.DropColumn(
                name: "AvatarWindowStart",
                table: "panda_profile_rate_limits");
        }
    }
}
