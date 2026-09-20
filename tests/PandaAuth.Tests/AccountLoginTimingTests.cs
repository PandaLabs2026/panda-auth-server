using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 登录时间侧信道回归：用户不存在时也必须付出一次密码哈希校验代价。
/// 只用「校验是否被调用」断言，不用计时断言——计时在 CI 上不稳定。
/// </summary>
public class AccountLoginTimingTests
{
    private static LoginViewModel UnknownUser(string userName = "ghost-user") => new()
    {
        UserName = userName,
        Password = "Sup3r$ecret-Password",
    };

    [Fact]
    public async Task UnknownUser_StillVerifiesPasswordOnceAgainstDummyHash()
    {
        var hasher = new RecordingPasswordHasher();
        using var provider = TestUserStoreHost.Create(passwordHasher: hasher);
        var controller = TestUserStoreHost.CreateAccountController(provider, hasher);
        var model = UnknownUser();

        var result = await controller.Login(model, CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        Assert.Equal(1, hasher.VerifyCalls);

        // 被校验的必须是那份固定 dummy 哈希（真实 Argon2 PHC 串），而不是空串或占位常量：
        // 否则校验会立即返回，侧信道依旧存在。
        Assert.NotNull(hasher.LastHashedPassword);
        Assert.StartsWith("$argon2id$", hasher.LastHashedPassword);
        Assert.Equal(model.Password, hasher.LastProvidedPassword);
        // 只断 PHC 前缀无法区分 dummy 哈希与任何别的真实哈希（两者前缀相同），
        // 故直接与单例持有的那份 dummy 哈希比对。
        Assert.Equal(provider.GetRequiredService<DummyPasswordHash>().Value, hasher.LastHashedPassword);
    }

    [Fact]
    public async Task UnknownUser_IsAuditedAsUserNotFound()
    {
        var hasher = new RecordingPasswordHasher();
        using var provider = TestUserStoreHost.Create(passwordHasher: hasher);
        var controller = TestUserStoreHost.CreateAccountController(provider, hasher);
        var model = UnknownUser();

        await controller.Login(model, CancellationToken.None);

        var dbContext = provider.GetRequiredService<PandaAuthDbContext>();
        var entry = await dbContext.LoginLogs.SingleAsync();
        Assert.Equal(model.UserName, entry.UserName);
        Assert.False(entry.Succeeded);
        Assert.Equal("user_not_found", entry.FailureReason);
    }

    [Fact]
    public async Task FrozenAccount_StillVerifiesPasswordOnceAgainstDummyHash()
    {
        // 冻结分支与「用户不存在」分支保持同一代价：文案已明示冻结，但耗时不应再额外区分路径。
        var hasher = new RecordingPasswordHasher();
        using var provider = TestUserStoreHost.Create(passwordHasher: hasher);
        var userManager = provider.GetRequiredService<UserService>();
        var frozen = new PandaUser { UserName = "frozen-user", Status = UserStatus.Frozen };
        Assert.True((await userManager.CreateAsync(frozen, "Sup3r$ecret-Password")).Succeeded);

        var controller = TestUserStoreHost.CreateAccountController(provider, hasher);
        var model = UnknownUser("frozen-user");

        var result = await controller.Login(model, CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        Assert.Equal(1, hasher.VerifyCalls);
        // 与未知用户路径一致：校验的是固定 dummy 哈希，而不是该账号的真实哈希。
        // 注意断言强度：两者都是 $argon2id$ PHC 串，只断前缀无法区分——把控制器里的
        // dummyPasswordHash.Value 换成 user.PasswordHash，前缀断言照样通过。
        // 故显式断言「不是该账号的真实哈希」且「就是单例持有的那份 dummy 哈希」。
        Assert.NotNull(hasher.LastHashedPassword);
        Assert.StartsWith("$argon2id$", hasher.LastHashedPassword);
        Assert.NotEqual(frozen.PasswordHash, hasher.LastHashedPassword);
        Assert.Equal(provider.GetRequiredService<DummyPasswordHash>().Value, hasher.LastHashedPassword);
    }

    [Fact]
    public async Task DummyHash_IsComputedOnlyOnce_AcrossAttempts()
    {
        // dummy 哈希若每次现算，未知用户名会变成「一次哈希 + 一次校验」，比真实用户更慢。
        var hasher = new RecordingPasswordHasher();
        using var provider = TestUserStoreHost.Create(passwordHasher: hasher);

        // 每次登录新建控制器（等价于 MVC 的每请求一实例）。
        await TestUserStoreHost.CreateAccountController(provider, hasher)
            .Login(UnknownUser(), CancellationToken.None);
        await TestUserStoreHost.CreateAccountController(provider, hasher)
            .Login(UnknownUser("another-ghost"), CancellationToken.None);

        Assert.Equal(2, hasher.VerifyCalls);
        Assert.Equal(1, hasher.HashCalls);
    }

    /// <summary>记录调用次数的 hasher 替身；哈希转发给真实 Argon2 实现，保证被校验的是一份真实哈希。</summary>
    private sealed class RecordingPasswordHasher : IPasswordHasher
    {
        private readonly Argon2idPasswordHasher _inner = new();

        public int HashCalls { get; private set; }

        public int VerifyCalls { get; private set; }

        public string? LastHashedPassword { get; private set; }

        public string? LastProvidedPassword { get; private set; }

        public string Hash(string password)
        {
            HashCalls++;
            return _inner.Hash(password);
        }

        public PasswordVerificationOutcome Verify(
            string? hashedPassword, string providedPassword)
        {
            VerifyCalls++;
            LastHashedPassword = hashedPassword;
            LastProvidedPassword = providedPassword;
            return _inner.Verify(hashedPassword, providedPassword);
        }
    }
}
