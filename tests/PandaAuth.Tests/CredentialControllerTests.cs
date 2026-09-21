using System.Security.Claims;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// CredentialController 安全路径测试：防枚举中性、发送门控（仅 Active 账号）、
/// 重置成功后令牌吊销与安全戳刷新、错误验证码拒绝。OTP 生命周期见 OtpServiceTests。
/// </summary>
public class CredentialControllerTests
{
    private sealed class StubEmailSender : IEmailSender
    {
        private static readonly Regex TokenPattern = new("[A-Za-z0-9_-]{43}", RegexOptions.Compiled);
        public ConcurrentQueue<(string Email, string Subject, string Body)> Messages { get; } = new();

        public Task SendVerificationCodeAsync(string email, string code, CancellationToken ct)
            => throw new InvalidOperationException("The legacy OTP path must not be used.");

        public Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct)
        {
            Messages.Enqueue((email, subject, htmlBody));
            return Task.CompletedTask;
        }

        public string TakeToken()
        {
            Assert.True(Messages.TryDequeue(out var message));
            return Assert.Single(TokenPattern.Matches(message.Body).Select(match => match.Value));
        }
    }

    private static async Task<(CredentialController Controller, ServiceProvider Provider, StubEmailSender Sender, StubTokenRevoker Revoker, UserService Users)> CreateAsync()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMvcCore();
        services.AddDbContext<PandaAuthDbContext>(builder => builder.UseInMemoryDatabase(Guid.NewGuid().ToString("N")));
        services.AddUserStore();
        services.AddMemoryCache();
        services.AddAuthentication();
        services.AddSingleton<LoginRateLimiter>();
        services.AddSingleton<DummyPasswordHash>();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IEmailSender, StubEmailSender>();
        var revoker = new StubTokenRevoker();
        services.AddSingleton<ITokenRevoker>(revoker);
        services.AddScoped<OtpService>();
        services.AddScoped<AccountVerificationService>();
        services.AddScoped<SecurityEventWriter>();
        var provider = services.BuildServiceProvider();

        var users = provider.GetRequiredService<UserService>();
        var controller = new CredentialController(
            users,
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            provider.GetRequiredService<AccountVerificationService>(),
            provider.GetRequiredService<IEmailSender>(),
            provider.GetRequiredService<ITokenRevoker>(),
            provider.GetRequiredService<SecurityEventWriter>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<CredentialController>())
        {
            ControllerContext = new ControllerContext(new ActionContext(
                new DefaultHttpContext { RequestServices = provider },
                new RouteData(),
                new ControllerActionDescriptor())),
            TempData = new TempDataDictionary(new DefaultHttpContext(), new NullTempDataProvider()),
        };
        return (controller, provider, (StubEmailSender)provider.GetRequiredService<IEmailSender>(), revoker, users);
    }

    private static async Task<PandaUser> SeedUserAsync(
        UserService users,
        string email,
        UserStatus status = UserStatus.Active,
        bool emailConfirmed = true)
    {
        var user = new PandaUser
        {
            UserName = email,
            Email = email,
            Status = status,
            EmailConfirmed = emailConfirmed,
        };
        await users.CreateAsync(user, "Passw0rd!1234");
        return user;
    }

    [Fact]
    public async Task ForgotPassword_UnknownEmail_NeutralResponse_NoSend()
    {
        var (controller, _, sender, _, _) = await CreateAsync();

        var result = await controller.ForgotPassword(
            new ForgotPasswordViewModel { Email = "nobody@example.com" }, CancellationToken.None);

        // 中性跳转到重置页（无错误），且没有真实发送。
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("ResetPassword", redirect.ActionName);
        Assert.Equal("nobody@example.com", controller.TempData["ResetEmail"]);
        Assert.Empty(sender.Messages);
    }

    [Fact]
    public async Task ForgotPassword_FrozenAccount_IssuesButDoesNotSend()
    {
        var (controller, _, sender, _, users) = await CreateAsync();
        await SeedUserAsync(users, "frozen@example.com", UserStatus.Frozen);

        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "frozen@example.com" }, CancellationToken.None);

        // 签发照常（防枚举路径一致），发送被门控。
        Assert.Empty(sender.Messages);
    }

    [Fact]
    public async Task ForgotPassword_ActiveConfirmedAccount_SendsOneTimeToken()
    {
        var (controller, _, sender, _, users) = await CreateAsync();
        await SeedUserAsync(users, "ok@example.com");

        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "ok@example.com" }, CancellationToken.None);

        var message = Assert.Single(sender.Messages);
        Assert.Equal("ok@example.com", message.Email);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", sender.TakeToken());
    }

    [Fact]
    public async Task ResetPassword_CorrectCode_SwapsPassword_RevokesTokens_RefreshesStamp()
    {
        var (controller, provider, sender, revoker, users) = await CreateAsync();
        var user = await SeedUserAsync(users, "reset@example.com");
        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "reset@example.com" }, CancellationToken.None);
        var token = sender.TakeToken();
        var stampBefore = user.SecurityStamp;

        var result = await controller.ResetPassword(
            new ResetPasswordViewModel { Email = "reset@example.com", Token = token, NewPassword = "NewPass!2026x" },
            CancellationToken.None);

        // 跳回登录页并携带发起方 returnUrl（成功形态），凭据与令牌全部更新。
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Account", redirect.ControllerName);
        Assert.Equal("Login", redirect.ActionName);
        Assert.Equal("/", redirect.RouteValues?["returnUrl"]); // 无发起方上下文时使用安全本地根路径
        var reloaded = await users.FindByIdAsync(user.Id);
        Assert.False(await users.CheckPasswordAsync(reloaded!, "Passw0rd!1234"));
        Assert.True(await users.CheckPasswordAsync(reloaded!, "NewPass!2026x"));
        Assert.Equal([user.Id], revoker.RevokedUsers);
        Assert.NotEqual(stampBefore, reloaded!.SecurityStamp);
        var securityEvent = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().SecurityEvents);
        Assert.Equal("user.password_reset", securityEvent.EventType);
        Assert.Equal(user.Id, securityEvent.UserId);
    }

    [Fact]
    public async Task ResetPassword_ReturnUrlFromForgotFlowIsPreserved()
    {
        var (controller, _, sender, _, users) = await CreateAsync();
        await SeedUserAsync(users, "ctx@example.com");

        // 忘记密码携带发起方上下文（OIDC authorize URL）
        await controller.ForgotPassword(
            new ForgotPasswordViewModel { Email = "ctx@example.com", ReturnUrl = "/connect/authorize?client_id=admin-web" },
            CancellationToken.None);
        Assert.Equal("/connect/authorize?client_id=admin-web", controller.TempData["ReturnUrl"]);

        // GET 重置页把上下文放进表单模型
        var resetView = Assert.IsType<ViewResult>(controller.ResetPassword());
        var vm = Assert.IsType<ResetPasswordViewModel>(resetView.Model);
        Assert.Equal("/connect/authorize?client_id=admin-web", vm.ReturnUrl);

        // 重置成功 → 登录页带着 returnUrl（登录后回到原发起方而非门户首页）
        var token = sender.TakeToken();
        var result = await controller.ResetPassword(
            new ResetPasswordViewModel { Email = "ctx@example.com", Token = token, NewPassword = "NewPass!2026x", ReturnUrl = "/connect/authorize?client_id=admin-web" },
            CancellationToken.None);
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("/connect/authorize?client_id=admin-web", redirect.RouteValues?["returnUrl"]);
    }

    [Fact]
    public async Task ChangePassword_LocalReturnUrl_IsPreservedForCancelNavigation()
    {
        var (controller, _, _, _, _) = await CreateAsync();

        var result = controller.ChangePassword("/admin");

        var view = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<ChangePasswordViewModel>(view.Model);
        Assert.Equal("/admin", model.ReturnUrl);
    }

    [Fact]
    public async Task ChangePassword_ExternalReturnUrl_UsesRootForCancelNavigation()
    {
        var (controller, _, _, _, _) = await CreateAsync();

        var result = controller.ChangePassword("https://attacker.example/admin");

        var view = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<ChangePasswordViewModel>(view.Model);
        Assert.Equal("/", model.ReturnUrl);
    }

    [Fact]
    public async Task ChangePassword_InvalidSubmission_PreservesLocalReturnUrlForCancelNavigation()
    {
        var (controller, _, _, _, _) = await CreateAsync();
        controller.ModelState.AddModelError(nameof(ChangePasswordViewModel.CurrentPassword), "required");

        var result = await controller.ChangePassword(
            new ChangePasswordViewModel { ReturnUrl = "/admin" }, CancellationToken.None);

        var view = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<ChangePasswordViewModel>(view.Model);
        Assert.Equal("/admin", model.ReturnUrl);
    }

    [Fact]
    public async Task ForgotAndResetPassword_ExternalReturnUrl_IsNotPropagated()
    {
        var (controller, _, sender, _, users) = await CreateAsync();
        await SeedUserAsync(users, "safe@example.com");

        await controller.ForgotPassword(new ForgotPasswordViewModel
        {
            Email = "safe@example.com",
            ReturnUrl = "https://attacker.example/steal",
        }, CancellationToken.None);
        var token = sender.TakeToken();

        var result = await controller.ResetPassword(new ResetPasswordViewModel
        {
            Email = "safe@example.com",
            Token = token,
            NewPassword = "NewPass!2026x",
            ReturnUrl = "https://attacker.example/steal",
        }, CancellationToken.None);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("/", redirect.RouteValues?["returnUrl"]);
    }

    [Fact]
    public async Task EmailConfirmation_ConsumesPurposeBoundToken()
    {
        var (controller, _, sender, _, users) = await CreateAsync();
        var user = await SeedUserAsync(users, "confirm@example.com", emailConfirmed: false);
        controller.HttpContext.User = Principal(user.Id);

        var begin = await controller.SendEmailConfirmation(CancellationToken.None);
        Assert.IsType<RedirectToActionResult>(begin);
        var token = sender.TakeToken();
        var consume = await controller.ConfirmEmail(
            new ConfirmEmailViewModel { Token = token }, CancellationToken.None);

        Assert.IsType<RedirectToActionResult>(consume);
        Assert.True((await users.FindByIdAsync(user.Id))!.EmailConfirmed);
    }

    [Fact]
    public async Task ChangeEmail_RequiresConfirmedEmailAndCurrentPassword_ThenChangesOnTokenConsumption()
    {
        var (controller, _, sender, revoker, users) = await CreateAsync();
        var user = await SeedUserAsync(users, "old@example.com");
        controller.HttpContext.User = Principal(user.Id);

        var begin = await controller.ChangeEmail(new ChangeEmailViewModel
        {
            NewEmail = "new@example.com",
            CurrentPassword = "Passw0rd!1234",
            ReturnUrl = "/me",
        }, CancellationToken.None);
        Assert.IsType<RedirectToActionResult>(begin);
        var token = sender.TakeToken();

        var consume = await controller.ConfirmEmailChange(new ConfirmEmailChangeViewModel
        {
            NewEmail = "new@example.com",
            Token = token,
            ReturnUrl = "/me",
        }, CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(consume);
        Assert.Equal("/me", redirect.Url);
        var reloaded = await users.FindByIdAsync(user.Id);
        Assert.Equal("new@example.com", reloaded!.Email);
        Assert.True(reloaded.EmailConfirmed);
        Assert.Equal([user.Id], revoker.RevokedUsers);
    }

    [Fact]
    public async Task ChangePassword_UnconfirmedAccount_IsRejected()
    {
        var (controller, _, _, revoker, users) = await CreateAsync();
        var user = await SeedUserAsync(users, "unconfirmed@example.com", emailConfirmed: false);
        controller.HttpContext.User = Principal(user.Id);

        var result = await controller.ChangePassword(new ChangePasswordViewModel
        {
            CurrentPassword = "Passw0rd!1234",
            NewPassword = "NewPass!2026x",
        }, CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        Assert.True(controller.ModelState.ErrorCount > 0);
        Assert.True(await users.CheckPasswordAsync((await users.FindByIdAsync(user.Id))!, "Passw0rd!1234"));
        Assert.Empty(revoker.RevokedUsers);
    }

    [Fact]
    public async Task ResetPassword_WrongCode_Rejected_NothingChanges()
    {
        var (controller, _, sender, revoker, users) = await CreateAsync();
        var user = await SeedUserAsync(users, "reset2@example.com");
        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "reset2@example.com" }, CancellationToken.None);

        var result = await controller.ResetPassword(
            new ResetPasswordViewModel { Email = "reset2@example.com", Token = "not-the-token", NewPassword = "NewPass!2026x" },
            CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        Assert.True(controller.ModelState.ErrorCount > 0);
        Assert.True(await users.CheckPasswordAsync((await users.FindByIdAsync(user.Id))!, "Passw0rd!1234"));
        Assert.Empty(revoker.RevokedUsers);
    }

    private static ClaimsPrincipal Principal(string userId) => new(new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, userId)], "test"));
}

internal sealed class NullTempDataProvider : ITempDataProvider
{
    public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();

    public void SaveTempData(HttpContext context, IDictionary<string, object> values)
    {
    }
}
