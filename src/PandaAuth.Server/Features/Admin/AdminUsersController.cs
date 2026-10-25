using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 用户管理数据 API（admin BFF 专用，Bearer + admin 角色；路径不经公网）。
/// 冻结/重置/角色变更/注销都联动批量吊销：令牌即时失效是既定的安全边界要求。
/// </summary>
[Route("~/admin-api/users")]
[RequireConfirmedEmail]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = AdminApiAuthorization.PolicyName)]
public sealed class AdminUsersController(
    UserService userManager,
    RoleService roleManager,
    SessionSecurityService sessionSecurity,
    AdminAuditWriter audit,
    SecurityEventWriter securityEvents,
    PandaAuth.Server.Infrastructure.Security.Mfa.MfaOperationGrantService grants,
    PandaAuthDbContext db,
    ILogger<AdminUsersController> logger) : Controller
{
    internal const int MaxPageSize = 50;
    internal const int DefaultPageSize = 20;

    /// <summary>
    /// 用户列表：按用户名/邮箱模糊搜索、状态过滤、分页。
    /// 排序参数从宽（元仓 ADR 2026-10-11-admin-user-sessions-and-sorting）：
    /// orderBy 白名单 userName/email/createdAt（大小写不敏感），order 取 asc/desc；
    /// 缺省与非法值一律回退 createdAt+desc，不因探测性输入报错。
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] string? query,
        [FromQuery] UserStatus? status,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromQuery] string? orderBy,
        [FromQuery] string? order,
        CancellationToken cancellationToken)
    {
        var pageNumber = Math.Max(page ?? 1, 1);
        var size = Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize);

        var users = userManager.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query))
        {
            // 与 Identity 的默认规范化器（UpperInvariant）一致，大小写不敏感搜索。
            var normalized = query.Trim().ToUpperInvariant();
            users = users.Where(user =>
                user.NormalizedUserName!.Contains(normalized)
                || (user.NormalizedEmail != null && user.NormalizedEmail.Contains(normalized)));
        }

        if (status is { } statusFilter)
        {
            users = users.Where(user => user.Status == statusFilter);
        }

        var ascending = string.Equals(order?.Trim(), "asc", StringComparison.OrdinalIgnoreCase);
        IOrderedQueryable<PandaUser> ordered = (orderBy?.Trim().ToLowerInvariant()) switch
        {
            "username" => ascending ? users.OrderBy(user => user.NormalizedUserName!) : users.OrderByDescending(user => user.NormalizedUserName!),
            "email" => ascending ? users.OrderBy(user => user.NormalizedEmail!) : users.OrderByDescending(user => user.NormalizedEmail!),
            // 缺省与白名单外取值：createdAt 倒序（契约正本的从宽回退口径）。
            _ => ascending ? users.OrderBy(user => user.CreatedAt) : users.OrderByDescending(user => user.CreatedAt),
        };

        var total = await users.CountAsync(cancellationToken);
        var items = await ordered
            .Skip(PaginationOffset.Calculate(pageNumber, size))
            .Take(size)
            .Select(user => new AdminUserSummary(
                user.Id, user.UserName!, user.Email, user.Nickname, user.Status, user.CreatedAt))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminUserSummary>(items, total, pageNumber, size));
    }

    /// <summary>
    /// 建号：密码缺省时服务端生成合规随机密码（明文仅本次响应返回一次）。
    /// 需要八小时内任一 MFA；建的是别人的号，不存在把自己锁在门外的路径。
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Create(
        [FromBody] AdminCreateUserRequest? request,
        CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasValidMfa(User)) return AdminApiAuthorization.MfaRequired();

        if (request is null || string.IsNullOrWhiteSpace(request.UserName))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "用户名不能为空",
                detail: "必须提供 UserName。");
        }

        var generated = string.IsNullOrEmpty(request.Password);
        var password = generated ? AdminPasswordGenerator.Generate() : request.Password!;

        var user = new PandaUser
        {
            UserName = request.UserName.Trim(),
            Email = string.IsNullOrWhiteSpace(request.Email) ? null : request.Email.Trim(),
            EmailConfirmed = false,
            Nickname = string.IsNullOrWhiteSpace(request.Nickname) ? null : request.Nickname.Trim(),
            Region = string.IsNullOrWhiteSpace(request.Region) ? null : request.Region.Trim(),
            RegisterChannel = RegisterChannel.Admin,
        };

        // Identity 负责规范化、唯一性校验与密码策略：任何失败都以 400 带回原始描述。
        var create = await userManager.CreateAsync(user, password);
        if (!create.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "建号失败",
                detail: string.Join("; ", create.Errors.Select(error => error.Description)));
        }

        // 部分成功也要留痕：账号一旦建成即写入审计；授角色失败时明文初始密码不返回，
        // 响应里明确指引「重置密码」补救——审计缺失会让这条安全轨迹在第一次操作上就断链。
        string? roleGrantError = null;
        if (request.GrantAdminRole)
        {
            // 预检角色存在：AddToRoleAsync 对缺失角色抛 InvalidOperationException 而非返回失败结果。
            if (!await roleManager.RoleExistsAsync(PandaUser.AdminRole))
            {
                roleGrantError = "admin 角色不存在（种子未执行？）";
            }
            else
            {
                var grant = await userManager.AddToRoleAsync(user, PandaUser.AdminRole);
                if (!grant.Succeeded)
                {
                    roleGrantError = string.Join("; ", grant.Errors.Select(error => error.Description));
                }
            }
        }

        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserCreate, "user", user.Id,
                new
                {
                    userName = user.UserName,
                    generatedPassword = generated,
                    grantAdminRole = request.GrantAdminRole && roleGrantError is null,
                    roleGrantError,
                },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.created", user.Id,
            new { generatedPassword = generated, grantAdminRole = request.GrantAdminRole && roleGrantError is null }), cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 创建了用户 {UserId}（{UserName}）。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName);

        if (roleGrantError is not null)
        {
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "账号已创建但授予管理员角色失败",
                detail: $"{roleGrantError}。账号已可用；明文初始密码未返回，请用「重置密码」重新生成，并稍后经角色管理补授。");
        }

        return Ok(new AdminCreateUserResponse(user.Id, user.UserName!, user.Email, generated ? password : null));
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Detail(string id)
    {
        var user = await userManager.FindByIdAsync(id);
        return user is null ? NotFound() : Ok(await DetailOf(user));
    }

    /// <summary>冻结 / 解冻。幂等：状态未变化时不产生吊销与审计。冻结后该用户全部有效令牌即时吊销。</summary>
    [HttpPost("{id}/status")]
    public async Task<IActionResult> SetStatus(
        string id,
        [FromBody] AdminUserStatusRequest? request,
        CancellationToken cancellationToken)
    {
        if (await MfaOperationGrantGate.ConsumeAsync(this, grants, securityEvents,
                User.FindFirst(Claims.Subject)?.Value ?? string.Empty, MfaOperations.AdminSetStatus, id,
                new Dictionary<string, string?> { ["status"] = request?.Status.ToString() }, cancellationToken)
            is { } grantDenied)
        {
            return grantDenied;
        }
        // Deleted 是注销语义（软删除），不经本端点设置——注销走专门的 deactivate 端点（逐字确认）。
        if (request is null || request.Status is not (UserStatus.Active or UserStatus.Frozen))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "无效的状态变更",
                detail: "status 只接受 Active 或 Frozen。");
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (DeletedGuard(user) is { } blocked)
        {
            return blocked;
        }

        // 封禁自冻结（含反向自解冻）：冻结自己是把自己锁在门外——冻结账号无法登录任何端点，
        // 解铃还须另一个管理员；与自重置封禁（ResetPassword）同一口径（2026-09-20 用户拍板）。
        var statusActorId = User.FindFirst(Claims.Subject)?.Value;
        if (string.Equals(user.Id, statusActorId, StringComparison.Ordinal))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "不能变更自己的账号状态",
                detail: "冻结自己会把当前管理会话立即锁在门外，且冻结账号无法登录任何端点。");
        }

        if (user.Status == request.Status)
        {
            return Ok(SummaryOf(user));
        }

        var previous = user.Status;
        await using var transaction = await AccountSecurityTransaction.BeginAsync(db, cancellationToken);
        user.Status = request.Status;
        user.SecurityStamp = Guid.NewGuid().ToString();
        user.UpdatedAt = DateTimeOffset.UtcNow;
        var update = await userManager.UpdateAsync(user);
        if (!update.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "状态更新失败",
                detail: string.Join("; ", update.Errors.Select(error => error.Description)));
        }

        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: cancellationToken);
        var action = request.Status == UserStatus.Frozen ? AdminAuditAction.UserFreeze : AdminAuditAction.UserUnfreeze;
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, action, "user", user.Id,
                new { userName = user.UserName, from = previous.ToString(), to = request.Status.ToString() },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.status_changed", user.Id,
            new { from = previous.ToString(), to = request.Status.ToString() }), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 将用户 {UserId}（{UserName}）状态由 {Previous} 变更为 {Status}。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName, previous, request.Status);

        return Ok(SummaryOf(user));
    }

    /// <summary>
    /// 重置密码：不传 NewPassword 则服务端生成合规随机密码；明文仅本次响应返回一次。
    /// 成功后吊销该用户全部令牌并刷新安全戳（Cookie 会话随之失效）。
    /// </summary>
    [HttpPost("{id}/reset-password")]
    public async Task<IActionResult> ResetPassword(
        string id,
        [FromBody] AdminResetPasswordRequest? request,
        CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasValidMfa(User)) return AdminApiAuthorization.MfaRequired();

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (DeletedGuard(user) is { } blocked)
        {
            return blocked;
        }

        // 封禁自重置：管理员重置自己的密码会跳过旧密码验证并强制下线自己（会话与令牌全部吊销），
        // 新密码只能靠响应卡片一次性带回——一旦没接住就被锁在门外。改自己的密码属自助流程
        // （旧密码验证），随 0.4 自助凭据管理交付（2026-09-19 用户拍板）。
        var actorId = User.FindFirst(Claims.Subject)?.Value;
        if (string.Equals(user.Id, actorId, StringComparison.Ordinal))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "不能重置自己的密码",
                detail: "管理端重置会强制下线目标账号的全部会话（包括你当前的管理台会话）。修改自己的密码请使用自助改密流程。");
        }

        var generated = string.IsNullOrEmpty(request?.NewPassword);
        var password = generated ? AdminPasswordGenerator.Generate() : request!.NewPassword!;

        // Once a valid reset is accepted, finish its security side effects even if the browser
        // disconnects. Keep the user password, outstanding recovery proofs, token revocation and
        // audit rows in one database transaction where supported.
        cancellationToken.ThrowIfCancellationRequested();
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(cancellationToken)
            : null;

        var now = DateTimeOffset.UtcNow;
        var pendingPasswordResets = await db.PasswordResetRequests
            .Where(item => item.Purpose == PasswordResetPurpose.PasswordReset &&
                           item.SubjectId == user.Id && item.ConsumedAt == null)
            .ToListAsync(CancellationToken.None);
        foreach (var pending in pendingPasswordResets)
            pending.ConsumedAt = now;

        // ReplacePasswordAsync（新哈希+安全戳轮换）经 UserService 单次 SaveAsync 落库：
        // 密码策略校验先于任何写入，失败即零变更（不存在「已移除旧密码再回滚」的中间态）；
        // 并发冲突由 UserService 内部以重载-重试消化。
        var add = await userManager.ReplacePasswordAsync(user, password);
        if (!add.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "新密码不合规",
                detail: string.Join("; ", add.Errors.Select(error => error.Description)));
        }

        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: CancellationToken.None);
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserResetPassword, "user", user.Id,
                new { userName = user.UserName, generated }, HttpContext.Connection.RemoteIpAddress?.ToString()),
            CancellationToken.None);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.password_reset", user.Id, new { generated }), CancellationToken.None);
        if (transaction is not null) await transaction.CommitAsync(CancellationToken.None);
        logger.LogInformation(
            "管理员 {Actor} 重置了用户 {UserId}（{UserName}）的密码。", User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName);

        return Ok(new AdminResetPasswordResponse(password));
    }

    /// <summary>
    /// 角色全量替换：Roles 即目标用户的完整角色集合。无变化时幂等（不吊销不审计）。
    /// 角色只写入访问令牌（AT 有效期 10 分钟），变更后吊销全部令牌保证即时生效。
    /// </summary>
    [HttpPut("{id}/roles")]
    public async Task<IActionResult> UpdateRoles(
        string id,
        [FromBody] AdminUserRolesRequest? request,
        CancellationToken cancellationToken)
    {
        if (await MfaOperationGrantGate.ConsumeAsync(this, grants, securityEvents,
                User.FindFirst(Claims.Subject)?.Value ?? string.Empty, MfaOperations.AdminUpdateRoles, id,
                new Dictionary<string, string?>
                {
                    // 角色集合按 Ordinal 排序后拼接：授权绑定的是集合内容，与请求里的顺序无关。
                    ["roles"] = request?.Roles is null
                        ? null
                        : string.Join(",", request.Roles.Order(StringComparer.Ordinal)),
                }, cancellationToken)
            is { } grantDenied)
        {
            return grantDenied;
        }
        if (request?.Roles is null || request.Roles.Any(string.IsNullOrWhiteSpace))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "无效的角色集合",
                detail: "Roles 不能为空且不得包含空白项。");
        }

        // 比较口径与 Identity 一致（规范化后大小写不敏感）：否则「ADMIN」这类大小写变体
        // 会被误判为差异，把本应幂等的请求折进增删路径再撞上 AlreadyInRole 失败。
        var targetRoles = request.Roles
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        foreach (var role in targetRoles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                return Problem(statusCode: StatusCodes.Status400BadRequest, title: "未知角色",
                    detail: $"角色 {role} 不存在。");
            }
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (DeletedGuard(user) is { } blocked)
        {
            return blocked;
        }

        // 封禁自降级：移除自己的 admin 角色后当前会话未必立刻失效（角色在 AT 里），
        // 但令牌一过期/一刷新即 403，解铃还须另一个管理员——与自冻结同一口径。
        var actorId = User.FindFirst(Claims.Subject)?.Value;
        if (string.Equals(user.Id, actorId, StringComparison.Ordinal)
            && !targetRoles.Contains(PandaUser.AdminRole, StringComparer.OrdinalIgnoreCase))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "不能移除自己的管理员角色",
                detail: "移除后你的下一次令牌刷新将被拒绝，且无法再进入管理台。请由另一位管理员操作。");
        }

        var currentRoles = await userManager.GetRolesAsync(user);
        var toAdd = targetRoles.Except(currentRoles, StringComparer.OrdinalIgnoreCase).ToArray();
        var toRemove = currentRoles.Except(targetRoles, StringComparer.OrdinalIgnoreCase).ToArray();
        if (toAdd.Length == 0 && toRemove.Length == 0)
        {
            return Ok(await DetailOf(user));
        }

        await using var transaction = await AccountSecurityTransaction.BeginAsync(db, cancellationToken);
        string? failure = null;
        foreach (var role in toAdd)
        {
            var add = await userManager.AddToRoleAsync(user, role);
            if (!add.Succeeded)
            {
                failure = $"授予角色 {role} 失败：{string.Join("; ", add.Errors.Select(error => error.Description))}";
                break;
            }
        }

        if (failure is null)
        {
            foreach (var role in toRemove)
            {
                var remove = await userManager.RemoveFromRoleAsync(user, role);
                if (!remove.Succeeded)
                {
                    failure = $"移除角色 {role} 失败：{string.Join("; ", remove.Errors.Select(error => error.Description))}";
                    break;
                }
            }
        }

        user.UpdatedAt = DateTimeOffset.UtcNow;
        if (failure is not null)
            return Problem(statusCode: StatusCodes.Status409Conflict, title: "角色变更失败", detail: failure);
        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: cancellationToken);
        var actualRoles = await userManager.GetRolesAsync(user);
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserUpdateRoles, "user", user.Id,
                new { userName = user.UserName, from = currentRoles.ToArray(), to = actualRoles.ToArray() },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.roles_changed", user.Id,
            new { from = currentRoles.ToArray(), to = actualRoles.ToArray() }), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        logger.LogInformation(
            "管理员 {Actor} 将用户 {UserId}（{UserName}）的角色由 [{Previous}] 变更为 [{Current}]。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName,
            string.Join(",", currentRoles), string.Join(",", actualRoles));

        return Ok(await DetailOf(user));
    }

    /// <summary>
    /// 解锁：清除临时锁定与连续失败计数。幂等：未被锁定且无失败计数时不产生审计。
    /// 不吊销令牌——锁定只挡新登录，不使既有令牌失效，解锁亦然。
    /// </summary>
    [HttpPost("{id}/unlock")]
    public async Task<IActionResult> Unlock(string id, CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasValidMfa(User)) return AdminApiAuthorization.MfaRequired();

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (DeletedGuard(user) is { } blocked)
        {
            return blocked;
        }

        var lockedNow = user.LockoutEnd is { } lockoutEnd && lockoutEnd > DateTimeOffset.UtcNow;
        if (!lockedNow && user.AccessFailedCount == 0)
        {
            return Ok(await DetailOf(user));
        }

        var previousLockoutEnd = user.LockoutEnd;
        var previousFailedCount = user.AccessFailedCount;
        user.UpdatedAt = DateTimeOffset.UtcNow;
        var clearLockout = await userManager.SetLockoutEndDateAsync(user, null);
        if (!clearLockout.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "解除锁定失败",
                detail: string.Join("; ", clearLockout.Errors.Select(error => error.Description)));
        }

        var resetCount = await userManager.ResetAccessFailedCountAsync(user);
        if (!resetCount.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "重置失败计数失败",
                detail: string.Join("; ", resetCount.Errors.Select(error => error.Description)));
        }

        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserUnlock, "user", user.Id,
                new { userName = user.UserName, previousLockoutEnd, previousFailedCount },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.unlocked", user.Id, new { previousLockoutEnd, previousFailedCount }), cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 解除了用户 {UserId}（{UserName}）的登录锁定。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName);

        return Ok(await DetailOf(user));
    }

    /// <summary>
    /// 独立踢下线：仅吊销该用户全部 OIDC 令牌（AT/RT 即时失效），不动账号状态/凭据/安全戳。
    /// 与冻结的吊销步骤同一通道（SessionSecurityService）；user.tokens_revoked 安全事件由
    /// TokenRevocationService 内部发出，此处不重复记录。契约正本见元仓 ADR 2026-10-11。
    /// </summary>
    [HttpPost("{id}/revoke-tokens")]
    public async Task<IActionResult> RevokeTokens(string id, CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasValidMfa(User)) return AdminApiAuthorization.MfaRequired();

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (DeletedGuard(user) is { } blocked)
        {
            return blocked;
        }

        // 自操作封禁：吊销自己的令牌等于踢掉当前管理台会话，自助登出已覆盖该需求
        //（与「不能变更自己的账号状态」同一口径，元仓 ADR 2026-10-11）。
        var actorId = User.FindFirst(Claims.Subject)?.Value;
        if (string.Equals(user.Id, actorId, StringComparison.Ordinal))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "不能对自己执行踢下线",
                detail: "该操作会吊销你当前管理台会话的令牌。退出登录即可自助下线。");
        }

        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: cancellationToken);
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserRevokeTokens, "user", user.Id,
                new { userName = user.UserName },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 吊销了用户 {UserId}（{UserName}）的全部令牌。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName);

        return Ok(await DetailOf(user));
    }

    /// <summary>
    /// 在线会话只读视图：该用户全部 Valid 状态 refresh_token 令牌的投影（AT 10 分钟即亡，
    /// authorization code 同理，都不构成会话语义）。只读、无审计、无 MFA 门禁
    /// （与 List/Detail 口径一致）；已注销账号允许查看（只读不影响终态语义）。
    /// 投影刻意不含 Payload/ReferenceId——令牌句柄与密文不出服务端。契约正本见元仓 ADR 2026-10-11。
    /// </summary>
    [HttpGet("{id}/sessions")]
    public async Task<IActionResult> Sessions(string id, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        var sessions = await db.Set<OpenIddictEntityFrameworkCoreToken>()
            .AsNoTracking()
            .Where(token => token.Subject == id
                && token.Status == Statuses.Valid
                && token.Type == TokenTypeHints.RefreshToken)
            .OrderByDescending(token => token.CreationDate)
            .Select(token => new AdminUserSession(
                // OpenIddict 实体的 Id/Type 声明为 string?，DB 列实际 NOT NULL——空联合并满足 DTO 非空契约。
                token.Id ?? string.Empty,
                token.Application!.ClientId,
                token.Type ?? string.Empty,
                token.CreationDate,
                token.ExpirationDate))
            .ToListAsync(cancellationToken);

        return Ok(sessions);
    }

    /// <summary>
    /// 资料编辑（PUT 全量语义：每个字段携带最终值，null 即清空）。邮箱变更会重置 EmailConfirmed。
    /// 允许编辑自己：吊销只造成一次可恢复的管理台重登，非死锁（自助资料页属 me 侧后续切片）。
    /// </summary>
    [HttpPut("{id}/profile")]
    public async Task<IActionResult> UpdateProfile(
        string id,
        [FromBody] AdminUserProfileRequest? request,
        CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasValidMfa(User)) return AdminApiAuthorization.MfaRequired();

        if (request is null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "无效的资料变更",
                detail: "请求体不能为空。");
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (DeletedGuard(user) is { } blocked)
        {
            return blocked;
        }

        var newEmail = string.IsNullOrWhiteSpace(request.Email) ? null : request.Email.Trim();
        var newNickname = string.IsNullOrWhiteSpace(request.Nickname) ? null : request.Nickname.Trim();
        var newRegion = string.IsNullOrWhiteSpace(request.Region) ? null : request.Region.Trim();

        var emailChanged = !string.Equals(user.Email, newEmail, StringComparison.OrdinalIgnoreCase);
        var nicknameChanged = !string.Equals(user.Nickname, newNickname, StringComparison.Ordinal);
        var regionChanged = !string.Equals(user.Region, newRegion, StringComparison.Ordinal);
        if (!emailChanged && !nicknameChanged && !regionChanged)
        {
            return Ok(await DetailOf(user));
        }

        await using var transaction = await AccountSecurityTransaction.BeginAsync(db, cancellationToken);
        if (emailChanged)
        {
            // 直写字段而非 SetEmailAsync：要同时覆盖「清空邮箱」（Email = null）这一分支。
            user.Email = newEmail;
            user.NormalizedEmail = newEmail is null ? null : userManager.NormalizeEmail(newEmail);
            user.EmailConfirmed = false;
        }

        user.Nickname = newNickname;
        user.Region = newRegion;
        user.SecurityStamp = Guid.NewGuid().ToString();
        user.UpdatedAt = DateTimeOffset.UtcNow;
        var update = await userManager.UpdateAsync(user);
        if (!update.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "资料更新失败",
                detail: string.Join("; ", update.Errors.Select(error => error.Description)));
        }

        // nickname/role 一样会进访问令牌 claim（profile scope），吊销保证新资料即时生效。
        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: cancellationToken);
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserUpdateProfile, "user", user.Id,
                new { userName = user.UserName, emailChanged, nicknameChanged, regionChanged },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.profile_updated", user.Id,
            new { emailChanged, nicknameChanged, regionChanged }), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 更新了用户 {UserId}（{UserName}）的资料（email={EmailChanged}, nickname={NicknameChanged}, region={RegionChanged}）。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName, emailChanged, nicknameChanged, regionChanged);

        return Ok(await DetailOf(user));
    }

    /// <summary>
    /// 重置两步验证：本批不保留旧凭据；管理员明确解除 MFA 阻断并吊销令牌。
    /// </summary>
    [HttpPost("{id}/reset-2fa")]
    public async Task<IActionResult> ResetTwoFactor(string id, CancellationToken cancellationToken)
    {
        if (await MfaOperationGrantGate.ConsumeAsync(this, grants, securityEvents,
                User.FindFirst(Claims.Subject)?.Value ?? string.Empty, MfaOperations.AdminResetTwoFactor, id,
                null, cancellationToken)
            is { } grantDenied)
        {
            return grantDenied;
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        if (DeletedGuard(user) is { } blocked)
        {
            return blocked;
        }

        var actorId = User.FindFirst(Claims.Subject)?.Value;
        if (string.IsNullOrEmpty(actorId) || string.Equals(actorId, user.Id, StringComparison.Ordinal))
        {
            return BadRequest(new { error = "管理员不能恢复自己的 MFA。" });
        }

        var now = DateTimeOffset.UtcNow;
        // 重置是一个整体：因子撤销、恢复码清空、安全戳轮换、令牌吊销必须同进同退。
        // 任一保存失败都不能返回 200——否则调用方会以为 MFA 已重置，实际旧因子仍有效。
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(cancellationToken)
            : null;
        user.TwoFactorEnabled = false;
        foreach (var credential in await db.WebAuthnCredentials.Where(item => item.UserId == user.Id && item.RevokedAt == null).ToListAsync(cancellationToken)) credential.RevokedAt = credential.UpdatedAt = now;
        foreach (var factor in await db.TotpFactors.Where(item => item.UserId == user.Id && item.RevokedAt == null).ToListAsync(cancellationToken)) factor.RevokedAt = now;

        // 恢复码是独立的 step-up 凭据：因子撤销后必须整体作废，不能留下“旧码仍可过 8 小时门禁”的尾巴。
        var recoveryCodes = await db.MfaRecoveryCodes
            .Where(code => code.UserId == user.Id)
            .ToListAsync(cancellationToken);
        db.MfaRecoveryCodes.RemoveRange(recoveryCodes);

        var stamp = await userManager.UpdateSecurityStampAsync(user);
        if (!stamp.Succeeded)
        {
            if (transaction is not null) await transaction.RollbackAsync(cancellationToken);
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "重置两步验证失败",
                detail: string.Join("; ", stamp.Errors.Select(error => error.Description)));
        }

        db.MfaRecoveryEvents.Add(new MfaRecoveryEvent
        {
            ActorUserId = actorId,
            TargetUserId = user.Id,
            Reason = MfaRecoveryEvent.AdminResetReason,
            AuthenticationMethod = MfaClaimTypes.WebAuthn,
            CreatedAt = now,
        });
        await db.SaveChangesAsync(cancellationToken);
        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: cancellationToken);
        if (transaction is not null) await transaction.CommitAsync(cancellationToken);

        await audit.RecordAsync(AdminAuditing.Entry(User!, AdminAuditAction.UserResetTwoFactor, "user", user.Id, new { recovery = true }, HttpContext.Connection.RemoteIpAddress?.ToString()), cancellationToken);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.mfa_reset", user.Id, new { recovery = true }), cancellationToken);
        return Ok(await DetailOf(user));
    }

    /// <summary>
    /// 注销（软删除，终态）：不经 SetStatus——注销是高危不可逆操作，必须逐字回填目标用户名确认。
    /// 注销后账号无法登录、全部令牌吊销；本批无恢复端点（恢复属未来需求）。
    /// </summary>
    [HttpPost("{id}/deactivate")]
    public async Task<IActionResult> Deactivate(
        string id,
        [FromBody] AdminDeactivateRequest? request,
        CancellationToken cancellationToken)
    {
        if (await MfaOperationGrantGate.ConsumeAsync(this, grants, securityEvents,
                User.FindFirst(Claims.Subject)?.Value ?? string.Empty, MfaOperations.AdminDeactivate, id,
                new Dictionary<string, string?> { ["confirmUserName"] = request?.ConfirmUserName }, cancellationToken)
            is { } grantDenied)
        {
            return grantDenied;
        }
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return NotFound();
        }

        // 防误触主门禁：确认名与目标用户名逐字相等才继续。
        if (request is null || !string.Equals(request.ConfirmUserName, user.UserName, StringComparison.Ordinal))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "确认用户名不匹配",
                detail: "注销为不可恢复操作，必须在请求中原样提供目标用户的 UserName。");
        }

        // 封禁自注销：注销账号无法登录任何端点——把自己锁死在门外，解铃须直接改库。
        var actorId = User.FindFirst(Claims.Subject)?.Value;
        if (string.Equals(user.Id, actorId, StringComparison.Ordinal))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "不能注销自己的账号",
                detail: "注销后该账号无法登录任何端点，包括你当前的管理台会话。");
        }

        if (user.Status == UserStatus.Deleted)
        {
            return Ok(await DetailOf(user));
        }

        var previous = user.Status;
        await using var transaction = await AccountSecurityTransaction.BeginAsync(db, cancellationToken);
        user.Status = UserStatus.Deleted;
        user.SecurityStamp = Guid.NewGuid().ToString();
        user.UpdatedAt = DateTimeOffset.UtcNow;
        var update = await userManager.UpdateAsync(user);
        if (!update.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "注销失败",
                detail: string.Join("; ", update.Errors.Select(error => error.Description)));
        }

        await sessionSecurity.RevokeUserAuthorizationsAsync(user.Id, cancellationToken: cancellationToken);
        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.UserDeactivate, "user", user.Id,
                new { userName = user.UserName, from = previous.ToString() },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        await securityEvents.RecordAsync(SecurityEventEntryFor(
            "user.deactivated", user.Id, new { from = previous.ToString() }), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        logger.LogInformation(
            "管理员 {Actor} 注销了用户 {UserId}（{UserName}）。",
            User.FindFirst(Claims.Subject)?.Value, user.Id, user.UserName);

        return Ok(await DetailOf(user));
    }

    /// <summary>
    /// 终态守卫：已注销（Deleted）账号拒绝一切账号级变更（状态/资料/角色/解锁/凭据）——
    /// 否则一次解冻误点就能「复活」账号，绕过注销端点的逐字确认门禁。
    /// Deactivate 端点刻意不经此守卫：它自己依赖「已注销 → 幂等返回」语义。
    /// </summary>
    private IActionResult? DeletedGuard(PandaUser user)
        => user.Status == UserStatus.Deleted
            ? Problem(statusCode: StatusCodes.Status400BadRequest, title: "账号已注销",
                detail: "注销为终态，不可再变更；恢复须直接操作数据库。")
            : null;

    private async Task<AdminUserDetail> DetailOf(PandaUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        return new AdminUserDetail(
            user.Id, user.UserName!, user.Email, user.EmailConfirmed, user.Nickname, user.Status,
            [.. roles], user.LockoutEnd, user.AccessFailedCount, user.TwoFactorEnabled,
            user.RegisterChannel, user.Region, user.CreatedAt, user.UpdatedAt);
    }

    private static AdminUserSummary SummaryOf(PandaUser user)
        => new(user.Id, user.UserName!, user.Email, user.Nickname, user.Status, user.CreatedAt);

    private SecurityEventEntry SecurityEventEntryFor(string eventType, string userId, object? metadata)
        => new(
            eventType,
            userId,
            User.FindFirst(Claims.Subject)?.Value,
            "user",
            userId,
            User.FindFirst(MfaClaimTypes.Method)?.Value,
            metadata,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent.ToString(),
            HttpContext.TraceIdentifier);
}
