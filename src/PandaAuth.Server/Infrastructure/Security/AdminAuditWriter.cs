using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// 管理操作审计写入器（模板与 <see cref="LoginAuditWriter"/> 同构：scoped、单方法、直接落库）。
/// 调用方负责在**操作成功后**写入——审计行本身不应是失败操作的副作用。
/// </summary>
public sealed class AdminAuditWriter(PandaAuthDbContext dbContext)
{
    public async Task RecordAsync(AdminAuditLog entry, CancellationToken cancellationToken = default)
    {
        dbContext.AdminAuditLogs.Add(entry);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
