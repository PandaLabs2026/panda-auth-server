using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>
/// 登录时间侧信道拉平用的固定 dummy 哈希。
/// 用户不存在时对这份哈希执行一次等价校验，使「用户存在 / 用户不存在」两条路径都付出一次
/// Argon2 代价——否则不存在的用户名会显著更快返回，仍可用于枚举账号（错误文案已统一，但时序泄漏）。
/// </summary>
/// <remarks>
/// 该哈希惰性计算一次并常驻缓存：若每次尝试现算，未知用户名会变成「一次哈希 + 一次校验」，
/// 反而比真实用户更慢，侧信道依旧存在。
/// 持有者必须是单例，而 <see cref="IPasswordHasher{TUser}"/> 注册为 scoped，
/// 故此处只缓存哈希字符串，校验仍由调用方用自己作用域内的 hasher 执行；
/// 首次计算也通过 <see cref="IServiceScopeFactory"/> 取 DI 中注册的 hasher，
/// 保证替换哈希实现（算法或参数变化）时 dummy 哈希与真实哈希保持同一口径。
/// </remarks>
public sealed class DummyPasswordHash
{
    /// <summary>dummy 哈希的源密码，与任何真实账号无关。</summary>
    private const string SourcePassword = "panda-auth-timing-equalization-dummy-password";

    private readonly Lazy<string> _hash;

    public DummyPasswordHash(IServiceScopeFactory scopeFactory)
    {
        _hash = new Lazy<string>(() =>
        {
            using var scope = scopeFactory.CreateScope();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<PandaAuthUser>>();
            return hasher.HashPassword(new PandaAuthUser(), SourcePassword);
        }, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>固定 dummy 哈希（PHC 字符串），首次访问时计算一次。</summary>
    public string Value => _hash.Value;
}
