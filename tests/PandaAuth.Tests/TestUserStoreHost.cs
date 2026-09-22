using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Tests;

/// <summary>
/// 控制器测试用的 Identity 容器：EF InMemory 存储 + 真实 UserManager/SignInManager。
/// 不手写框架类型的替身（其构造函数不稳定），只替换需要观测的协作者。
/// 依赖一律从根容器解析：普通 ServiceProvider 不校验作用域，且同一实例贯穿整个用例，
/// 便于直接读取写入的审计记录。
/// </summary>
internal static class TestUserStoreHost
{
    internal static ServiceProvider Create(
        AuthOptions? options = null, IPasswordHasher? passwordHasher = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddControllersWithViews();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddHttpContextAccessor();
        services.AddSingleton(Options.Create(options ?? new AuthOptions()));
        var databaseName = Guid.NewGuid().ToString("N");
        services.AddDbContext<PandaAuthDbContext>(builder => builder
            .UseInMemoryDatabase(databaseName));
        services.AddAuthentication();
        services.AddUserStore();
        services.AddMemoryCache();
        services.AddSingleton<LoginRateLimiter>();
        services.AddScoped<LoginAuditWriter>();
        services.AddScoped<ClaimsPolicyService>();
        services.AddScoped<ExternalIdentityService>();
        services.AddScoped<SecurityEventWriter>();
        services.AddSingleton<ITokenRevoker, NoopTokenRevoker>();
        services.AddScoped<SessionSecurityService>();
        services.AddSingleton<DummyPasswordHash>();

        if (passwordHasher is not null)
        {
            services.AddSingleton(passwordHasher);
        }

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// 登录控制器；HttpContext 为空白（仅用于取 RemoteIpAddress 与 User-Agent）。
    /// 每次「请求」都要新建实例：ModelState 在实例内累积错误，复用同一实例会让第二次登录
    /// 直接命中 !ModelState.IsValid 而提前返回（真实 MVC 每条请求新建控制器）。
    /// </summary>
    internal static AccountController CreateAccountController(
        ServiceProvider provider, IPasswordHasher passwordHasher)
        => new(
            provider.GetRequiredService<UserService>(),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            provider.GetRequiredService<LoginAuditWriter>(),
            passwordHasher,
            provider.GetRequiredService<DummyPasswordHash>())
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext { RequestServices = provider } },
        };

    internal static AuthorizationController CreateAuthorizationController(ServiceProvider provider)
        => new(
            provider.GetRequiredService<UserService>(),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<ClaimsPolicyService>())
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext { RequestServices = provider } },
        };
}

internal sealed class NoopTokenRevoker : ITokenRevoker
{
    public Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
        => Task.CompletedTask;
}
