using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>登录审计：完整记录 IP、设备（UA）、时间、结果、失败原因与客户端 App。</summary>
public sealed class LoginAuditWriter(PandaAuthDbContext dbContext)
{
    public async Task RecordAsync(LoginLog entry, CancellationToken cancellationToken = default)
    {
        dbContext.LoginLogs.Add(entry);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
