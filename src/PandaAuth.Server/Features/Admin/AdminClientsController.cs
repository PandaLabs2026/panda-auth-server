using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 客户端管理数据 API。读走 EF 直查（列表/分页），写走 <c>IOpenIddictApplicationManager</c>
/// （Populate/Update 的并发与哈希语义已在 DbSeeder 被测试钉住，此处不另起炉灶）。
/// 密钥轮换用 <c>UpdateAsync(application, secret)</c>——那是唯一会重新哈希的路径。
/// </summary>
[Route("~/admin-api/clients")]
[RequireConfirmedEmail]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Policy = AdminApiAuthorization.PolicyName)]
public sealed class AdminClientsController(
    PandaAuthDbContext dbContext,
    IOpenIddictApplicationManager applications,
    AdminAuditWriter audit,
    ILogger<AdminClientsController> logger) : Controller
{
    internal const int MaxPageSize = 50;
    internal const int DefaultPageSize = 20;

    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        var pageNumber = Math.Max(page ?? 1, 1);
        var size = Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize);

        var clients = dbContext.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking();
        var total = await clients.CountAsync(cancellationToken);
        var items = await clients
            .OrderBy(client => client.ClientId)
            .Skip((pageNumber - 1) * size)
            .Take(size)
            .Select(client => new AdminClientSummary(
                client.ClientId!, client.DisplayName, client.ClientType!, client.ConsentType!))
            .ToListAsync(cancellationToken);

        return Ok(new AdminPageResult<AdminClientSummary>(items, total, pageNumber, size));
    }

    /// <summary>权限目录：UI 复选组与写入校验共用的单一事实源（见 <see cref="PermissionCatalog"/>）。</summary>
    [HttpGet("options")]
    public IActionResult Options()
        => Ok(new AdminClientOptions(PermissionCatalog.Groups));

    [HttpGet("{clientId}")]
    public async Task<IActionResult> Detail(string clientId)
    {
        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        return Ok(await BuildDetailAsync(applications, application));
    }

    /// <summary>整体替换回调 / 登出白名单。替换序列沿用 DbSeeder 的实证结论：先 Populate 出可变副本，改完再写回。</summary>
    [HttpPut("{clientId}/redirect-uris")]
    public async Task<IActionResult> UpdateRedirectUris(
        string clientId,
        [FromBody] AdminRedirectUrisRequest? request,
        CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasRecentWebAuthn(User)) return Forbid();
        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        if (request is null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "请求体缺失");
        }

        var redirectUris = request.RedirectUris ?? [];
        var postLogoutUris = request.PostLogoutRedirectUris ?? [];
        if (redirectUris.Count == 0)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "回调白名单不能为空",
                detail: "清空 RedirectUris 会让该客户端永远无法完成登录回调。");
        }

        var invalid = redirectUris.Concat(postLogoutUris)
            .FirstOrDefault(uri => !IsAbsoluteHttpUri(uri));
        if (invalid is not null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "白名单包含非法地址",
                detail: $"{invalid} —— 必须是绝对的 http(s) URL。");
        }

        var previousRedirect = (await applications.GetRedirectUrisAsync(application)).ToArray();
        var previousPostLogout = (await applications.GetPostLogoutRedirectUrisAsync(application)).ToArray();

        var updated = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(updated, application);
        updated.RedirectUris.Clear();
        foreach (var uri in redirectUris)
        {
            updated.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        updated.PostLogoutRedirectUris.Clear();
        foreach (var uri in postLogoutUris)
        {
            updated.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        await applications.PopulateAsync(application, updated);
        await applications.UpdateAsync(application);

        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.ClientUpdateUris, "client", clientId,
                new { redirectUris, postLogoutUris, previousRedirectUris = previousRedirect, previousPostLogoutRedirectUris = previousPostLogout },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation("管理员 {Actor} 更新了客户端 {ClientId} 的回调/登出白名单。", User.Identity?.Name, clientId);

        return Ok(await BuildDetailAsync(applications, application));
    }

    /// <summary>整体替换权限集。每个权限串都必须落在 <see cref="PermissionCatalog"/> allowlist 内。</summary>
    [HttpPut("{clientId}/permissions")]
    public async Task<IActionResult> UpdatePermissions(
        string clientId,
        [FromBody] AdminPermissionsRequest? request,
        CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasRecentWebAuthn(User)) return Forbid();
        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        if (request is null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "请求体缺失");
        }

        var permissions = (request.Permissions ?? []).Distinct(StringComparer.Ordinal).ToArray();
        if (permissions.Length == 0)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "权限集不能为空",
                detail: "没有任何权限的客户端无法通过任何端点认证。");
        }

        var rejected = permissions.FirstOrDefault(permission => !PermissionCatalog.IsAllowed(permission));
        if (rejected is not null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "包含未知权限",
                detail: $"{rejected} 不在服务端 allowlist 内（GET admin-api/clients/options 可取目录）。");
        }

        var previous = (await applications.GetPermissionsAsync(application)).ToArray();

        var updated = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(updated, application);
        updated.Permissions.Clear();
        foreach (var permission in permissions)
        {
            updated.Permissions.Add(permission);
        }

        await applications.PopulateAsync(application, updated);
        await applications.UpdateAsync(application);

        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.ClientUpdatePermissions, "client", clientId,
                new { permissions, previousPermissions = previous },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation("管理员 {Actor} 更新了客户端 {ClientId} 的权限集。", User.Identity?.Name, clientId);

        return Ok(await BuildDetailAsync(applications, application));
    }

    /// <summary>
    /// 轮换客户端密钥：生成 32 字节随机值，明文仅本次响应返回一次，库内只落哈希。
    /// ⚠️ 若轮换的是 admin-web / me-web 自身，须同步更新服务器 env 并重跑 --migrate 对账，
    /// 否则该客户端以旧密钥刷新令牌会全部失败（UI 已有提示，这里不再拦截）。
    /// </summary>
    [HttpPost("{clientId}/rotate-secret")]
    public async Task<IActionResult> RotateSecret(string clientId, CancellationToken cancellationToken)
    {
        if (!AdminApiAuthorization.HasRecentWebAuthn(User)) return Forbid();
        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        if (!string.Equals(await applications.GetClientTypeAsync(application), ClientTypes.Confidential, StringComparison.Ordinal))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "非机密客户端",
                detail: "公共客户端（PKCE）没有密钥，无从轮换。");
        }

        var secret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        // 必须走 UpdateAsync(application, secret)：唯一会重新哈希的路径（DbSeeder 注释的实证结论）。
        await applications.UpdateAsync(application, secret);

        await audit.RecordAsync(
            AdminAuditing.Entry(User!, AdminAuditAction.ClientRotateSecret, "client", clientId,
                new { note = "secret rotated; plaintext returned once, not stored" },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation("管理员 {Actor} 轮换了客户端 {ClientId} 的密钥。", User.Identity?.Name, clientId);

        return Ok(new AdminRotateSecretResponse(clientId, secret));
    }

    internal static async Task<AdminClientDetail> BuildDetailAsync(
        IOpenIddictApplicationManager applications, object application)
        => new(
            (await applications.GetClientIdAsync(application))!,
            await applications.GetDisplayNameAsync(application),
            (await applications.GetClientTypeAsync(application)) ?? string.Empty,
            (await applications.GetConsentTypeAsync(application)) ?? string.Empty,
            [.. await applications.GetRedirectUrisAsync(application)],
            [.. await applications.GetPostLogoutRedirectUrisAsync(application)],
            [.. await applications.GetPermissionsAsync(application)],
            [.. await applications.GetRequirementsAsync(application)]);

    private static bool IsAbsoluteHttpUri(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
}
