using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;

namespace PandaAuth.Server.Infrastructure.Persistence;

public class PandaAuthDbContext(DbContextOptions<PandaAuthDbContext> options)
    : IdentityDbContext<PandaAuthUser, PandaAuthRole, string>(options)
{
    public DbSet<LoginLog> LoginLogs => Set<LoginLog>();

    public DbSet<SigningKeyRecord> SigningKeys => Set<SigningKeyRecord>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<LoginLog>(entity =>
        {
            entity.ToTable("login_logs");
            entity.HasIndex(x => new { x.UserId, x.CreatedAt });
            entity.HasIndex(x => x.UserName);
            // 保留策略（LoginLogRetentionService）按 `CreatedAt < cutoff` 分批删除，谓词不含 UserId，
            // 用不上上面那个以 UserId 打头的复合索引 —— 没有这一条时每日清理会走全表扫描。
            entity.HasIndex(x => x.CreatedAt);
        });

        builder.Entity<SigningKeyRecord>(entity =>
        {
            entity.ToTable("signing_keys");
            entity.HasKey(x => x.KeyId);
        });
    }
}
