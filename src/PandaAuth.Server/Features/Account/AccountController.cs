using Microsoft.AspNetCore.Mvc;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Features.Account;

[Route("~/account")]
public sealed class AccountController(
    UserService userManager,
    LoginSessionService signInManager,
    LoginRateLimiter loginRateLimiter,
    LoginAuditWriter loginAudit,
    IPasswordHasher passwordHasher,
    DummyPasswordHash dummyPasswordHash) : Controller
{
    /// <summary>dummy 校验用的占位用户；Argon2 校验只依赖哈希与口令，不读取该实例的状态。</summary>
    private static readonly PandaUser DummyUser = new();

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        // 自助重置/改密（CredentialController）完成后跳转回来时带一次性提示。
        if (TempData["Notice"] is string notice)
        {
            ViewData["Notice"] = notice;
        }

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
        PandaUser? signedInUser = null;
        string? failureReason = "user_not_found";

        if (user is not null && user.Status != UserStatus.Active)
        {
            failureReason = "account_frozen";
            // 冻结状态在文案里已明示（不是秘密），但响应耗时不应额外区分路径：
            // 与「用户不存在」一样支付一次等价哈希代价，避免各分支耗时形成可枚举的指纹。
            passwordHasher.Verify(dummyPasswordHash.Value, model.Password);
            await loginAudit.RecordAsync(BuildLog(), cancellationToken);
            return ViewWithError("账号已被冻结，请联系管理员。");
        }

        if (user is not null)
        {
            var result = await signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
            succeeded = result.Succeeded;
            signedInUser = result.User;
            failureReason = succeeded ? null
                : result.IsLockedOut ? "locked_out"
                : result.IsNotAllowed ? "not_allowed"
                : "wrong_password";
        }
        else
        {
            // 时间侧信道拉平：用户不存在时同样付出一次 Argon2 代价（对固定 dummy 哈希校验一次），
            // 使两条路径耗时接近。否则「不存在的用户名」明显更快返回，响应内容再一致也可枚举账号。
            passwordHasher.Verify(dummyPasswordHash.Value, model.Password);
        }

        await loginAudit.RecordAsync(BuildLog(), cancellationToken);

        if (!succeeded)
        {
            return ViewWithError(failureReason == "locked_out"
                ? "失败次数过多，账号已临时锁定，请稍后再试。"
                : "用户名或密码错误。");
        }

        await signInManager.SignInAsync(HttpContext, signedInUser!, isPersistent: false);
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
        await signInManager.SignOutAsync(HttpContext);
        return Redirect("/");
    }
}
