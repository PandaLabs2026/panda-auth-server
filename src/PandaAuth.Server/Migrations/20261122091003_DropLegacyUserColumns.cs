using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class DropLegacyUserColumns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                SET LOCAL lock_timeout = '5s';
                LOCK TABLE public.panda_users IN ACCESS EXCLUSIVE MODE;

                DO $guard$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM public.panda_users
                        WHERE "AvatarUrl" IS NOT NULL OR "Region" IS NOT NULL
                    ) THEN
                        RAISE EXCEPTION USING ERRCODE = '23514',
                            MESSAGE = 'Resolve legacy avatar and region values before removing user columns.';
                    END IF;
                END
                $guard$;

                ALTER TABLE public.panda_users
                    DROP COLUMN "Nickname" RESTRICT,
                    DROP COLUMN "AvatarUrl" RESTRICT,
                    DROP COLUMN "Region" RESTRICT;
                """);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException(
                "Use the verified backup recovery procedure to restore legacy columns and their values.");
        }
    }
}
