using System.Text.Json;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

public sealed record SecurityEventEntry(
    string EventType,
    string? UserId,
    string? ActorUserId,
    string? TargetType,
    string? TargetId,
    string? AuthenticationMethod,
    object? Metadata,
    string? IpAddress,
    string? UserAgent,
    string? CorrelationId);

/// <summary>
/// 统一安全事件写入端口。调用方提交 DTO，避免直接构造持久化实体或重复序列化 Metadata。
/// </summary>
public sealed class SecurityEventWriter(PandaAuthDbContext dbContext, TimeProvider clock)
{
    public async Task RecordAsync(SecurityEventEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(entry.EventType);

        dbContext.SecurityEvents.Add(new SecurityEvent
        {
            UserId = entry.UserId,
            ActorUserId = entry.ActorUserId,
            EventType = entry.EventType,
            TargetType = entry.TargetType,
            TargetId = entry.TargetId,
            AuthenticationMethod = entry.AuthenticationMethod,
            Metadata = entry.Metadata is null ? null : JsonSerializer.Serialize(entry.Metadata),
            IpAddress = entry.IpAddress,
            UserAgent = entry.UserAgent,
            CreatedAt = clock.GetUtcNow(),
            CorrelationId = entry.CorrelationId,
        });

        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
