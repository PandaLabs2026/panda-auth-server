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
        });

        builder.Entity<SigningKeyRecord>(entity =>
        {
            entity.ToTable("signing_keys");
            entity.HasKey(x => x.KeyId);
        });
    }
}
