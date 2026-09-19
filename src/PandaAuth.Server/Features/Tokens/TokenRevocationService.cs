using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Infrastructure.Persistence;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Tokens;

/// <summary>
/// Token 批量吊销的门面接口：改密、冻结账号、注销等生命周期事件接入调用。
/// 抽接口是为了让 Admin 控制器的测试可以替换实现（EF InMemory 不支持其内部的 ExecuteUpdateAsync）。
/// </summary>
public interface ITokenRevoker
{
    /// <summary>吊销某用户的全部有效令牌（可选限定客户端）。</summary>
    Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default);

    /// <summary>吊销某客户端名下的全部有效令牌。</summary>
    Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default);
}

public sealed class TokenRevocationService(PandaAuthDbContext dbContext) : ITokenRevoker
{
    public async Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
    {
        var query = dbContext.Set<OpenIddictEntityFrameworkCoreToken>()
            .Where(token => token.Subject == userId && token.Status == Statuses.Valid);

        if (clientId is not null)
        {
            // 默认 Token 实体不携带客户端外键标量，经 Application 导航属性关联。
            query = query.Where(token => token.Application!.ClientId == clientId);
        }

        await query.ExecuteUpdateAsync(
            setters => setters.SetProperty(token => token.Status, Statuses.Revoked),
            cancellationToken);
    }

    public async Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
    {
        await dbContext.Set<OpenIddictEntityFrameworkCoreToken>()
            .Where(token => token.Status == Statuses.Valid && token.Application!.ClientId == clientId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(token => token.Status, Statuses.Revoked),
                cancellationToken);
    }
}
