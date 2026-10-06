using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// 邮箱确认门回归（与 Admin 面 RequireConfirmedEmailAttribute 策略对齐）：未确认邮箱的用户
/// 可以登录（自助确认流程需要），但授权端拒绝发码（access_denied）；email claim 只在已确认时
/// 进令牌（纵深，覆盖刷新等重建主体的路径）。
/// </summary>
public class EmailConfirmedGateTests
{
    private const string CorrectPassword = "Strong!Pass123";

    [Fact]
    public async Task UnconfirmedEmail_AuthorizeReturnsAccessDenied()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await CreateUserAsync(provider, emailConfirmed: false);

        var action = await AuthorizeAsync(provider, user);

        // access_denied 经 OpenIddict 透传 302 回 redirect_uri；登录会话本身不被注销（保留自助确认入口）。
        var forbid = Assert.IsType<ForbidResult>(action);
        Assert.Contains(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, forbid.AuthenticationSchemes);
        Assert.Equal(Errors.AccessDenied,
            forbid.Properties?.Items[OpenIddictServerAspNetCoreConstants.Properties.Error]);
        Assert.Equal("邮箱未确认，请先完成邮箱验证。",
            forbid.Properties?.Items[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription]);
    }

    [Fact]
    public async Task ConfirmedEmail_AuthorizeProceedsToSignIn()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await CreateUserAsync(provider, emailConfirmed: true);

        var action = await AuthorizeAsync(provider, user);

        var signIn = Assert.IsType<SignInResult>(action);
        Assert.Equal(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, signIn.AuthenticationScheme);
    }

    [Fact]
    public async Task UnconfirmedEmail_CanStillLogIn()
    {
        // 刻意保留登录能力：重发确认邮件/点击确认链接都在登录后的自助流程里，锁登录会形成死锁。
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "unconfirmed-login", Email = "unconfirmed@example.com" };
        await users.CreateAsync(user, CorrectPassword);

        var controller = TestUserStoreHost.CreateAccountController(
            provider, provider.GetRequiredService<IPasswordHasher>());
        var action = await controller.Login(
            new LoginViewModel { UserName = "unconfirmed-login", Password = CorrectPassword }, CancellationToken.None);

        var redirect = Assert.IsType<LocalRedirectResult>(action);
        Assert.Equal("/me/", redirect.Url);
        Assert.NotNull(Cookie(controller.HttpContext, "PandaAuth.Login.v2"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmailClaim_OnlyWrittenWhenConfirmed(bool emailConfirmed)
    {
        using var provider = TestUserStoreHost.Create();
        var user = await CreateUserAsync(provider, emailConfirmed);

        var principal = await TestUserStoreHost.CreateAuthorizationController(provider)
            .CreatePrincipalAsync(user, [Scopes.OpenId, Scopes.Email], await SourcePrincipalAsync(provider, user));

        if (emailConfirmed)
        {
            Assert.Equal("gate@example.com", principal.FindFirst(Claims.Email)!.Value);
        }
        else
        {
            Assert.Null(principal.FindFirst(Claims.Email));
        }
    }

    // ---- 基建 ----

    private static async Task<PandaUser> CreateUserAsync(ServiceProvider provider, bool emailConfirmed)
    {
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser
        {
            UserName = $"gate-{emailConfirmed}-{Guid.NewGuid():N}",
            Email = "gate@example.com",
            EmailConfirmed = emailConfirmed,
        };
        await users.CreateAsync(user, CorrectPassword);
        return user;
    }

    /// <summary>
    /// 以真实登录 cookie + 注入的 OpenIddict 服务端事务调用 Authorize：
    /// 透传控制器从 HttpContext feature 读取授权请求，从请求头登录 cookie 完成认证。
    /// </summary>
    private static async Task<IActionResult> AuthorizeAsync(ServiceProvider provider, PandaUser user)
    {
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        var context = (DefaultHttpContext)controller.HttpContext!;
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = await LoginCookieAsync(provider, user);
        context.Features.Set(new OpenIddictServerAspNetCoreFeature
        {
            Transaction = new OpenIddictServerTransaction
            {
                Request = new OpenIddictRequest
                {
                    ClientId = "gate-client",
                    RedirectUri = "https://app.example.com/callback",
                    ResponseType = ResponseTypes.Code,
                    Scope = "openid email",
                },
            },
        });
        return await controller.Authorize();
    }

    private static async Task<string> LoginCookieAsync(ServiceProvider provider, PandaUser user)
    {
        using var scope = provider.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        await scope.ServiceProvider.GetRequiredService<LoginSessionService>().SignInAsync(context, user, false);
        return context.Response.Headers.SetCookie
            .Single(header => header!.StartsWith(LoginSessionService.Scheme + "=", StringComparison.Ordinal))!
            .Split(';')[0];
    }

    /// <summary>CreatePrincipalAsync 的 mfaSource：带合法认证时间的已验签主体（FleetHumanPrincipalClaims 要求）。</summary>
    private static async Task<ClaimsPrincipal> SourcePrincipalAsync(ServiceProvider provider, PandaUser user)
        => await TestUserStoreHost.AuthenticatedPrincipalAsync(provider, user);

    private static string? Cookie(HttpContext context, string name)
    {
        var pair = context.Response.Headers.SetCookie
            .Select(value => value!.Split(';')[0])
            .FirstOrDefault(value => value.StartsWith(name + "=", StringComparison.Ordinal));
        return pair is null ? null : pair[(name.Length + 1)..];
    }
}
