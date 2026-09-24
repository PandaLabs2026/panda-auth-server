using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PandaAuth.Server.Migrations
{
    /// <summary>
    /// 观察期届满后删除 ASP.NET Core Identity 遗留表（2026-09-20 迁移后保留 14 天只读观察，
    /// 独立评审见 meta 仓 docs/superpowers/specs/2026-09-23-asnet-legacy-tables-drop-review.md）。
    /// 只删旧表与其拒写触发器，不触碰任何 panda_* / OpenIddict 表。
    /// 删除不可逆：唯一回滚路径是迁移窗口前的 pg_dump 备份，Down 刻意失败关闭。
    /// </summary>
    public partial class AspNetLegacyTablesDrop : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // 先移除各表拒写触发器（触发器名固定为 panda_auth_legacy_identity_read_only，
            // 用 IF EXISTS 兜底，避免因名称差异中断删除）。
            foreach (var table in new[] { "AspNetUsers", "AspNetRoles", "AspNetUserRoles", "AspNetUserClaims", "AspNetRoleClaims", "AspNetUserLogins", "AspNetUserTokens" })
            {
                migrationBuilder.Sql($"DROP TRIGGER IF EXISTS panda_auth_legacy_identity_read_only ON \"{table}\";");
            }

            // 再删表：CASCADE 兜底清理残留外键；清单与 2026-09-23 备份实测一致。
            foreach (var table in new[] { "AspNetUserTokens", "AspNetUserLogins", "AspNetUserClaims", "AspNetRoleClaims", "AspNetUserRoles", "AspNetRoles", "AspNetUsers" })
            {
                migrationBuilder.Sql($"DROP TABLE IF EXISTS \"{table}\" CASCADE;");
            }
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new InvalidOperationException(
                "AspNet 遗留表删除不可逆：如需恢复，请用迁移窗口前的 pg_dump -Fc 备份在隔离环境恢复（镜像回滚不恢复数据库）。");
        }
    }
}
