using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations;

/// <inheritdoc />
public partial class SelfBuiltUserStore : Migration
{
    /// <summary>
    /// Copies the security-core subset of ASP.NET Identity while preserving legacy rows and IDs.
    /// The legacy tables remain read-only observation data until a separately scheduled
    /// retention-removal migration runs.
    /// </summary>
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "panda_roles",
            columns: table => new
            {
                Id = table.Column<string>(type: "text", nullable: false),
                Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                NormalizedName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                ConcurrencyStamp = table.Column<string>(type: "text", nullable: true)
            },
            constraints: table => table.PrimaryKey("PK_panda_roles", x => x.Id));

        migrationBuilder.CreateTable(
            name: "panda_users",
            columns: table => new
            {
                Id = table.Column<string>(type: "text", nullable: false),
                UserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                NormalizedUserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                NormalizedEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                EmailConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                PasswordHash = table.Column<string>(type: "text", nullable: true),
                TwoFactorEnabled = table.Column<bool>(type: "boolean", nullable: false),
                SecurityStamp = table.Column<string>(type: "text", nullable: true),
                ConcurrencyStamp = table.Column<string>(type: "text", nullable: true),
                LockoutEnabled = table.Column<bool>(type: "boolean", nullable: false),
                LockoutEnd = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                AccessFailedCount = table.Column<int>(type: "integer", nullable: false),
                Nickname = table.Column<string>(type: "text", nullable: true),
                AvatarUrl = table.Column<string>(type: "text", nullable: true),
                Status = table.Column<int>(type: "integer", nullable: false),
                RegisterChannel = table.Column<int>(type: "integer", nullable: false),
                Region = table.Column<string>(type: "text", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_panda_users", x => x.Id));

        migrationBuilder.CreateTable(
            name: "panda_user_roles",
            columns: table => new
            {
                UserId = table.Column<string>(type: "text", nullable: false),
                RoleId = table.Column<string>(type: "text", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_panda_user_roles", x => new { x.UserId, x.RoleId });
                table.ForeignKey("FK_panda_user_roles_panda_roles_RoleId", x => x.RoleId, "panda_roles", "Id", onDelete: ReferentialAction.Cascade);
                table.ForeignKey("FK_panda_user_roles_panda_users_UserId", x => x.UserId, "panda_users", "Id", onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex("IX_panda_roles_NormalizedName", "panda_roles", "NormalizedName", unique: true);
        migrationBuilder.CreateIndex("IX_panda_user_roles_RoleId", "panda_user_roles", "RoleId");
        migrationBuilder.CreateIndex("IX_panda_users_NormalizedEmail", "panda_users", "NormalizedEmail", unique: true);
        migrationBuilder.CreateIndex("IX_panda_users_NormalizedUserName", "panda_users", "NormalizedUserName", unique: true);

        // Block old Identity writers before reading any source data. The locks are held until
        // this migration transaction commits, so a cutover is one consistent snapshot.
        migrationBuilder.Sql("""
            LOCK TABLE "AspNetRoleClaims", "AspNetRoles", "AspNetUserClaims", "AspNetUserLogins",
                "AspNetUserRoles", "AspNetUsers", "AspNetUserTokens" IN SHARE ROW EXCLUSIVE MODE;
            """);

        // Unique indexes are created before copying: duplicates abort PostgreSQL's surrounding
        // migration transaction, preserving the legacy source unchanged.
        migrationBuilder.Sql("""
            INSERT INTO panda_users ("Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail",
                "EmailConfirmed", "PasswordHash", "TwoFactorEnabled", "SecurityStamp", "ConcurrencyStamp", "LockoutEnabled",
                "LockoutEnd", "AccessFailedCount", "Nickname", "AvatarUrl", "Status", "RegisterChannel",
                "Region", "CreatedAt", "UpdatedAt")
            SELECT "Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail",
                "EmailConfirmed", "PasswordHash", "TwoFactorEnabled", "SecurityStamp", "ConcurrencyStamp", "LockoutEnabled",
                "LockoutEnd", "AccessFailedCount", "Nickname", "AvatarUrl", "Status", "RegisterChannel",
                "Region", "CreatedAt", "UpdatedAt"
            FROM "AspNetUsers";
            """);
        migrationBuilder.Sql("""
            INSERT INTO panda_roles ("Id", "Name", "NormalizedName", "ConcurrencyStamp")
            SELECT "Id", "Name", "NormalizedName", "ConcurrencyStamp" FROM "AspNetRoles";
            INSERT INTO panda_user_roles ("UserId", "RoleId")
            SELECT "UserId", "RoleId" FROM "AspNetUserRoles";
            """);

        // Fail closed if an old binary remains connected after the one-shot cutover.
        migrationBuilder.Sql("""
            CREATE FUNCTION panda_auth_reject_legacy_identity_write()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'ASP.NET Identity observation tables are read-only after the PandaAuth user-store cutover'
                    USING ERRCODE = '55000';
            END;
            $$;

            DO $$
            DECLARE legacy_table text;
            BEGIN
                FOREACH legacy_table IN ARRAY ARRAY[
                    'AspNetRoleClaims', 'AspNetRoles', 'AspNetUserClaims', 'AspNetUserLogins',
                    'AspNetUserRoles', 'AspNetUsers', 'AspNetUserTokens'
                ]
                LOOP
                    EXECUTE format(
                        'CREATE TRIGGER panda_auth_legacy_identity_read_only BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION panda_auth_reject_legacy_identity_write()',
                        legacy_table);
                END LOOP;
            END;
            $$;
            """);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DO $$
            DECLARE legacy_table text;
            BEGIN
                FOREACH legacy_table IN ARRAY ARRAY[
                    'AspNetRoleClaims', 'AspNetRoles', 'AspNetUserClaims', 'AspNetUserLogins',
                    'AspNetUserRoles', 'AspNetUsers', 'AspNetUserTokens'
                ]
                LOOP
                    EXECUTE format('DROP TRIGGER IF EXISTS panda_auth_legacy_identity_read_only ON %I', legacy_table);
                END LOOP;
            END;
            $$;
            DROP FUNCTION IF EXISTS panda_auth_reject_legacy_identity_write();
            """);
        migrationBuilder.DropTable(name: "panda_user_roles");
        migrationBuilder.DropTable(name: "panda_roles");
        migrationBuilder.DropTable(name: "panda_users");
    }
}
