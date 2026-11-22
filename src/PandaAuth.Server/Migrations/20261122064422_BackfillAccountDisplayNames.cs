using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <inheritdoc />
    public partial class BackfillAccountDisplayNames : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Match String.Trim's Unicode whitespace. PostgreSQL counts characters in UTF-8,
            // so the 80-character limit also matches the profile API's Unicode scalar limit.
            migrationBuilder.Sql("""
                WITH candidates AS (
                    SELECT u."Id",
                        btrim(u."Nickname", U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') AS name
                    FROM panda_users u
                    LEFT JOIN panda_user_profiles p ON p."UserId" = u."Id"
                    WHERE u."Nickname" IS NOT NULL AND p."DisplayName" IS NULL
                ), changed AS (
                    INSERT INTO panda_user_profiles AS profile ("UserId", "DisplayName", "Revision", "UpdatedAt", "ContactEmailState")
                    SELECT "Id", name, replace(gen_random_uuid()::text, '-', ''), CURRENT_TIMESTAMP, 0
                    FROM candidates
                    WHERE char_length(name) BETWEEN 1 AND 80 AND name !~ '^[^[:space:]@]+@[^[:space:]@]+$'
                    ON CONFLICT ("UserId") DO UPDATE SET
                        "DisplayName" = EXCLUDED."DisplayName",
                        "Revision" = EXCLUDED."Revision",
                        "UpdatedAt" = EXCLUDED."UpdatedAt"
                    WHERE profile."DisplayName" IS NULL
                    RETURNING "UserId"
                )
                UPDATE panda_profile_contact_challenges c
                SET "State" = 5
                FROM changed
                WHERE c."UserId" = changed."UserId" AND c."State" IN (0, 1);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("Backfilled display names may have since been edited. Use the verified recovery procedure.");
        }
    }
}
