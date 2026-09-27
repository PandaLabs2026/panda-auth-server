using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Management;

/// <summary>
/// Management API 用户只读查询（M0）：Bearer M2M 令牌 + mgmt.users.read scope + panda-mgmt-api audience。
/// 与 admin BFF 数据 API 的区别：公开可达、按 scope 授权、零凭据字段、无会话/step-up 语义；
/// 用户写操作不在此面（仍走 admin BFF 人工通道）。
/// </summary>
[ApiController]
[Route("mgmt/v1/users")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = MgmtApiAuthorization.UsersReadPolicy)]
public sealed class ManagementUsersController(UserService userManager) : ControllerBase
{
    private const int DefaultPageSize = 20;
    private const int MaxPageSize = 100;

    /// <summary>分页查询：按用户名/邮箱模糊搜索（与 admin 列表同一规范化口径）；响应零凭据字段。</summary>
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] string? query,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var pageNumber = Math.Max(page ?? 1, 1);
        var size = Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize);

        var users = userManager.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query))
        {
            // 与 admin 列表一致：按规范化列 UpperInvariant 大小写不敏感搜索。
            var normalized = query.Trim().ToUpperInvariant();
            users = users.Where(user =>
                user.NormalizedUserName!.Contains(normalized)
                || (user.NormalizedEmail != null && user.NormalizedEmail.Contains(normalized)));
        }

        var total = await users.CountAsync(cancellationToken);
        var items = await users
            .OrderByDescending(user => user.CreatedAt)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .Select(user => new AdminUserSummary(
                user.Id, user.UserName!, user.Email, user.Nickname, user.Status, user.CreatedAt))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminUserSummary>(items, total, pageNumber, size));
    }
}
