using System.Net;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// Admin 控制器测试宿主：EF InMemory + 真 Identity/UserManager + 真 OpenIddict Core 管理器
/// （对齐 DbSeederTests 的模式）+ 可断言的 ITokenRevoker 桩。AddMvcCore 仅为给
/// Controller.Problem() 提供 ProblemDetailsFactory（错误路径测试需要）。
/// </summary>
internal static class AdminTestHost
{
    public static (ServiceProvider Provider, StubTokenRevoker Revoker) Create()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMvcCore();
        services.AddDbContext<PandaAuthDbContext>(builder => builder
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .UseOpenIddict());
        services.AddUserStore();
        services.AddOpenIddict()
            .AddCore(builder => builder.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        var revoker = new StubTokenRevoker();
        services.AddSingleton<ITokenRevoker>(revoker);
        services.AddScoped<AdminAuditWriter>();
        return (services.BuildServiceProvider(), revoker);
    }

    /// <summary>Bearer 令牌主体的等价物：sub/name/role（与 admin-web 的 AT claim 集一致）。</summary>
    public static ClaimsPrincipal AdminPrincipal()
        => new(new ClaimsIdentity(
        [
            new Claim(Claims.Subject, "actor-1"),
            new Claim(Claims.Name, "admin"),
            new Claim(Claims.Role, PandaAuthRoles.Admin),
            new Claim(MfaClaimTypes.Method, MfaClaimTypes.WebAuthn),
            new Claim(MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        ], "TestBearer", Claims.Name, Claims.Role));

    public static DefaultHttpContext HttpContext(IServiceProvider provider)
        => new()
        {
            RequestServices = provider,
            User = AdminPrincipal(),
            Connection = { RemoteIpAddress = IPAddress.Parse("203.0.113.10") },
        };
}

internal sealed class StubTokenRevoker : ITokenRevoker
{
    public List<string> RevokedUsers { get; } = [];

    public List<string> RevokedClients { get; } = [];

    public Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
    {
        RevokedUsers.Add(userId);
        return Task.CompletedTask;
    }

    public Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
    {
        RevokedClients.Add(clientId);
        return Task.CompletedTask;
    }
}

/// <summary>[Authorize] 是唯一把公网请求挡在 Admin API 外的门——用反射钉住三个控制器的每个动作。</summary>
public class AdminApiAuthorizationContractTests
{
    public static TheoryData<Type> AdminControllerTypes() =>
    [
        typeof(AdminUsersController),
        typeof(AdminClientsController),
        typeof(AdminAuditController),
    ];

    [Theory]
    [MemberData(nameof(AdminControllerTypes))]
    public void Controllers_RequireOpenIddictBearerSchemeAndAdminRole(Type controllerType)
    {
        // 控制器级特性覆盖全部动作；无 [AllowAnonymous]。
        Assert.DoesNotContain(controllerType.GetMethods(), method =>
            method.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute), true).Length > 0);

        var authorize = controllerType.GetCustomAttribute<Microsoft.AspNetCore.Authorization.AuthorizeAttribute>();
        Assert.NotNull(authorize);
        // 自定义 API 必须走 Validation 方案（Server 方案只对 /connect/* 提取身份）+ admin-api 策略。
        Assert.Equal(OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, authorize.AuthenticationSchemes);
        Assert.Equal(AdminApiAuthorization.PolicyName, authorize.Policy);
    }
}
