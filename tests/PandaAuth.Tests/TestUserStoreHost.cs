using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
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
using OpenIddict.Abstractions;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;

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
        AuthOptions? options = null, IPasswordHasher? passwordHasher = null, TimeProvider? clock = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddControllersWithViews();
        services.AddAntiforgery();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddHttpContextAccessor();
        services.AddSingleton(Options.Create(options ?? new AuthOptions()));
        services.AddScoped<TenantContextAccessor>();
        services.AddScoped<ITenantContextAccessor>(serviceProvider => serviceProvider.GetRequiredService<TenantContextAccessor>());
        var databaseName = Guid.NewGuid().ToString("N");
        services.AddDbContext<PandaAuthDbContext>(builder => builder
            .UseInMemoryDatabase(databaseName)
            .UseOpenIddict());
        services.AddAuthentication();
        services.AddUserStore();
        // AuthorizationController 依赖 IOpenIddictScopeManager（client_credentials 资源解析）；既有测试流不触发该路径。
        services.AddOpenIddict().AddCore(builder => builder.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        services.AddMemoryCache();
        services.AddSingleton<LoginRateLimiter>();
        services.AddScoped<LoginAuditWriter>();
        services.AddScoped<ClaimsPolicyService>();
        services.AddScoped<ExternalIdentityService>();
        services.AddScoped<SecurityEventWriter>();
        services.AddSingleton<ITokenRevoker, NoopTokenRevoker>();
        services.AddScoped<SessionSecurityService>();
        services.AddSingleton<DummyPasswordHash>();
        services.AddScoped<LoginMfaChallengeService>();

        if (passwordHasher is not null)
        {
            services.AddSingleton(passwordHasher);
        }

        if (clock is not null) services.AddSingleton(clock);

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// 登录控制器；HttpContext 为空白（仅用于取 RemoteIpAddress 与 User-Agent）。
    /// 每次「请求」都要新建实例：ModelState 在实例内累积错误，复用同一实例会让第二次登录
    /// 直接命中 !ModelState.IsValid 而提前返回（真实 MVC 每条请求新建控制器）。
    /// </summary>
    internal static AccountController CreateAccountController(
        ServiceProvider provider, IPasswordHasher passwordHasher,
        PandaAuth.Server.Infrastructure.Security.Mfa.MfaService? mfa = null,
        PandaAuth.Server.Infrastructure.Security.Mfa.LoginMfaChallengeService? loginMfaChallenges = null,
        SecurityEventWriter? securityEvents = null)
        => new(
            provider.GetRequiredService<UserService>(),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            provider.GetRequiredService<LoginAuditWriter>(),
            passwordHasher,
            provider.GetRequiredService<DummyPasswordHash>(),
            provider.GetRequiredService<IOptions<AuthOptions>>(),
            mfa,
            loginMfaChallenges,
            securityEvents)
        {
            // Url.IsLocalUrl（登录 MFA 分支）需要完整 ActionContext，仅有 HttpContext 会在 UrlHelper 构造时 NRE。
            ControllerContext = new ControllerContext(new ActionContext(
                new DefaultHttpContext { RequestServices = provider },
                new Microsoft.AspNetCore.Routing.RouteData(),
                new Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor())),
        };

    internal static AuthorizationController CreateAuthorizationController(ServiceProvider provider)
        => new(
            provider.GetRequiredService<UserService>(),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<ClaimsPolicyService>(),
            provider.GetRequiredService<IOpenIddictScopeManager>(),
            provider.GetRequiredService<ITenantContextAccessor>(),
            new TenantRedirectPolicy(),
            provider.GetRequiredService<LoginMfaChallengeService>())
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext { RequestServices = provider } },
        };

    internal static async Task<ClaimsPrincipal> AuthenticatedPrincipalAsync(
        ServiceProvider provider, PandaUser user, string? mfaMethod = null)
    {
        using var issueScope = provider.CreateScope();
        var context = new DefaultHttpContext { RequestServices = issueScope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        var sessions = issueScope.ServiceProvider.GetRequiredService<LoginSessionService>();
        if (mfaMethod is null) await sessions.SignInAsync(context, user, false);
        else await sessions.SignInWithMfaAsync(context, user, mfaMethod);

        using var verificationScope = provider.CreateScope();
        var verification = new DefaultHttpContext { RequestServices = verificationScope.ServiceProvider };
        verification.Request.Scheme = "https";
        verification.Request.Host = new HostString("localhost");
        verification.Request.Headers.Cookie = context.Response.Headers.SetCookie.Single()!.Split(';')[0];
        var ticket = await verification.AuthenticateAsync(LoginSessionService.Scheme);
        if (!ticket.Succeeded) throw new InvalidOperationException("Test login cookie did not authenticate.");
        return ticket.Principal!;
    }
}

internal sealed class NoopTokenRevoker : ITokenRevoker
{
    public Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
        => Task.CompletedTask;
}
