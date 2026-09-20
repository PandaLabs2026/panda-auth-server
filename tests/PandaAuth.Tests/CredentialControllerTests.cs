using System.Security.Claims;
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
        public List<(string Email, string Code)> VerificationCodes { get; } = [];

        public Task SendVerificationCodeAsync(string email, string code, CancellationToken ct)
        {
            VerificationCodes.Add((email, code));
            return Task.CompletedTask;
        }

        public Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct) => Task.CompletedTask;
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
        var provider = services.BuildServiceProvider();

        var users = provider.GetRequiredService<UserService>();
        var controller = new CredentialController(
            users,
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            provider.GetRequiredService<OtpService>(),
            provider.GetRequiredService<IEmailSender>(),
            provider.GetRequiredService<ITokenRevoker>(),
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

    private static async Task<PandaUser> SeedUserAsync(UserService users, string email, UserStatus status = UserStatus.Active)
    {
        var user = new PandaUser { UserName = email, Email = email, Status = status };
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
        Assert.Empty(sender.VerificationCodes);
    }

    [Fact]
    public async Task ForgotPassword_FrozenAccount_IssuesButDoesNotSend()
    {
        var (controller, _, sender, _, users) = await CreateAsync();
        await SeedUserAsync(users, "frozen@example.com", UserStatus.Frozen);

        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "frozen@example.com" }, CancellationToken.None);

        // 签发照常（防枚举路径一致），发送被门控。
        Assert.Empty(sender.VerificationCodes);
    }

    [Fact]
    public async Task ForgotPassword_ActiveAccount_SendsCode()
    {
        var (controller, _, sender, _, users) = await CreateAsync();
        await SeedUserAsync(users, "ok@example.com");

        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "ok@example.com" }, CancellationToken.None);

        var (email, code) = Assert.Single(sender.VerificationCodes);
        Assert.Equal("ok@example.com", email);
        Assert.Matches("^[0-9]{6}$", code);
    }

    [Fact]
    public async Task ResetPassword_CorrectCode_SwapsPassword_RevokesTokens_RefreshesStamp()
    {
        var (controller, _, sender, revoker, users) = await CreateAsync();
        var user = await SeedUserAsync(users, "reset@example.com");
        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "reset@example.com" }, CancellationToken.None);
        var code = sender.VerificationCodes.Single().Code;
        var stampBefore = user.SecurityStamp;

        var result = await controller.ResetPassword(
            new ResetPasswordViewModel { Email = "reset@example.com", Code = code, NewPassword = "NewPass!2026x" },
            CancellationToken.None);

        // 跳回登录页并携带发起方 returnUrl（成功形态），凭据与令牌全部更新。
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Account", redirect.ControllerName);
        Assert.Equal("Login", redirect.ActionName);
        Assert.Null(redirect.RouteValues?["returnUrl"]); // 本用例无发起方上下文
        var reloaded = await users.FindByIdAsync(user.Id);
        Assert.False(await users.CheckPasswordAsync(reloaded!, "Passw0rd!1234"));
        Assert.True(await users.CheckPasswordAsync(reloaded!, "NewPass!2026x"));
        Assert.Equal([user.Id], revoker.RevokedUsers);
        Assert.NotEqual(stampBefore, reloaded!.SecurityStamp);
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
        var code = sender.VerificationCodes.Single().Code;
        var result = await controller.ResetPassword(
            new ResetPasswordViewModel { Email = "ctx@example.com", Code = code, NewPassword = "NewPass!2026x", ReturnUrl = "/connect/authorize?client_id=admin-web" },
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
    public async Task ResetPassword_WrongCode_Rejected_NothingChanges()
    {
        var (controller, _, sender, revoker, users) = await CreateAsync();
        var user = await SeedUserAsync(users, "reset2@example.com");
        await controller.ForgotPassword(new ForgotPasswordViewModel { Email = "reset2@example.com" }, CancellationToken.None);

        var result = await controller.ResetPassword(
            new ResetPasswordViewModel { Email = "reset2@example.com", Code = "000000", NewPassword = "NewPass!2026x" },
            CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        Assert.True(controller.ModelState.ErrorCount > 0);
        Assert.True(await users.CheckPasswordAsync((await users.FindByIdAsync(user.Id))!, "Passw0rd!1234"));
        Assert.Empty(revoker.RevokedUsers);
    }
}

internal sealed class NullTempDataProvider : ITempDataProvider
{
    public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();

    public void SaveTempData(HttpContext context, IDictionary<string, object> values)
    {
    }
}
