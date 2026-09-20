using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;

namespace PandaAuth.Server.Infrastructure.Persistence;

public class PandaAuthDbContext(DbContextOptions<PandaAuthDbContext> options)
    : DbContext(options)
{
    public DbSet<PandaUser> Users => Set<PandaUser>();
    public DbSet<PandaRole> Roles => Set<PandaRole>();
    public DbSet<PandaUserRole> UserRoles => Set<PandaUserRole>();
    public DbSet<LoginLog> LoginLogs => Set<LoginLog>();

    public DbSet<AdminAuditLog> AdminAuditLogs => Set<AdminAuditLog>();

    public DbSet<VerificationCode> VerificationCodes => Set<VerificationCode>();

    public DbSet<SigningKeyRecord> SigningKeys => Set<SigningKeyRecord>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<PandaUser>(entity =>
        {
            entity.ToTable("panda_users");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.UserName).HasMaxLength(256);
            entity.Property(x => x.NormalizedUserName).HasMaxLength(256);
            entity.Property(x => x.Email).HasMaxLength(256);
            entity.Property(x => x.NormalizedEmail).HasMaxLength(256);
            entity.Property(x => x.ConcurrencyStamp).IsConcurrencyToken();
            entity.HasIndex(x => x.NormalizedUserName).IsUnique();
            entity.HasIndex(x => x.NormalizedEmail).IsUnique();
        });
        builder.Entity<PandaRole>(entity =>
        {
            entity.ToTable("panda_roles");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Name).HasMaxLength(256);
            entity.Property(x => x.NormalizedName).HasMaxLength(256);
            entity.Property(x => x.ConcurrencyStamp).IsConcurrencyToken();
            entity.HasIndex(x => x.NormalizedName).IsUnique();
        });
        builder.Entity<PandaUserRole>(entity =>
        {
            entity.ToTable("panda_user_roles");
            entity.HasKey(x => new { x.UserId, x.RoleId });
            entity.HasOne<PandaUser>().WithMany().HasForeignKey(x => x.UserId);
            entity.HasOne<PandaRole>().WithMany().HasForeignKey(x => x.RoleId);
        });

        builder.Entity<LoginLog>(entity =>
        {
            entity.ToTable("login_logs");
            entity.HasIndex(x => new { x.UserId, x.CreatedAt });
            entity.HasIndex(x => x.UserName);
            // 保留策略（LoginLogRetentionService）按 `CreatedAt < cutoff` 分批删除，谓词不含 UserId，
            // 用不上上面那个以 UserId 打头的复合索引 —— 没有这一条时每日清理会走全表扫描。
            entity.HasIndex(x => x.CreatedAt);
        });

        builder.Entity<AdminAuditLog>(entity =>
        {
            entity.ToTable("admin_audit_logs");
            // 管理台按操作者检索（「这个管理员干了什么」）与按时间线检索两个入口。
            entity.HasIndex(x => new { x.ActorUserId, x.CreatedAt });
            // 保留清理按 CreatedAt 谓词分批删除，同 login_logs 的理由需要单列索引。
            entity.HasIndex(x => x.CreatedAt);
        });

        builder.Entity<VerificationCode>(entity =>
        {
            entity.ToTable("verification_codes");
            // 频控（按邮箱数最近 1 分钟/1 小时）与校验检索都走 EmailHash + CreatedAt。
            entity.HasIndex(x => new { x.EmailHash, x.CreatedAt });
            // 保留清理按 ExpiresAt 谓词分批删除，同 login_logs 的理由需要单列索引。
            entity.HasIndex(x => x.ExpiresAt);
        });

        builder.Entity<SigningKeyRecord>(entity =>
        {
            entity.ToTable("signing_keys");
            entity.HasKey(x => x.KeyId);
        });
    }
}
