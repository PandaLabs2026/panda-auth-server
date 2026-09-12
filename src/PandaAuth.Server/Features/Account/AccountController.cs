using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Features.Account;

[Route("~/account")]
public sealed class AccountController(
    UserManager<PandaAuthUser> userManager,
    SignInManager<PandaAuthUser> signInManager,
    LoginRateLimiter loginRateLimiter,
    LoginAuditWriter loginAudit) : Controller
{
    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        return View(new LoginViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers.UserAgent.ToString();
        var normalizedUserName = model.UserName.Trim();

        using var ipLease = loginRateLimiter.AttemptByIp(ipAddress);
        if (!ipLease.IsAcquired)
        {
            return ViewWithError("尝试过于频繁，请稍后再试。");
        }

        using var accountLease = loginRateLimiter.AttemptByAccount(normalizedUserName);
        if (!accountLease.IsAcquired)
        {
            return ViewWithError("尝试过于频繁，请稍后再试。");
        }

        var user = await userManager.FindByNameAsync(normalizedUserName);
        var succeeded = false;
        string? failureReason = "user_not_found";

        if (user is not null && user.Status != UserStatus.Active)
        {
            failureReason = "account_frozen";
            await loginAudit.RecordAsync(BuildLog(), cancellationToken);
            return ViewWithError("账号已被冻结，请联系管理员。");
        }

        if (user is not null)
        {
            var result = await signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
            succeeded = result.Succeeded;
            failureReason = succeeded ? null
                : result.IsLockedOut ? "locked_out"
                : result.IsNotAllowed ? "not_allowed"
                : "wrong_password";
        }

        await loginAudit.RecordAsync(BuildLog(), cancellationToken);

        if (!succeeded)
        {
            return ViewWithError(failureReason == "locked_out"
                ? "失败次数过多，账号已临时锁定，请稍后再试。"
                : "用户名或密码错误。");
        }

        await signInManager.SignInAsync(user!, isPersistent: false);
        return LocalRedirect(string.IsNullOrWhiteSpace(model.ReturnUrl) ? "/" : model.ReturnUrl);

        IActionResult ViewWithError(string message)
        {
            ModelState.AddModelError(string.Empty, message);
            return View(model);
        }

        LoginLog BuildLog() => new()
        {
            UserId = user?.Id,
            UserName = normalizedUserName,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Succeeded = succeeded,
            FailureReason = failureReason,
        };
    }

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await signInManager.SignOutAsync();
        return Redirect("/");
    }
}
