using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Management;

/// <summary>
/// Management API 客户端 CRUD（M0）：Bearer M2M 令牌 + mgmt.clients.write/read + panda-mgmt-api audience。
/// 写路径与 admin 客户端管理同构（Populate/Update 实证模式、UpdateAsync(app, secret) 唯一重哈希路径），
/// 区别：无 MFA step-up（M2M 主体），按 scope 授权，写审计走 mgmt.client.* 前缀（同表 admin_audit_logs）。
/// 保留客户端（第一方客户端）对管理 API 完全只读——避免自动化通道误伤种子对账与 BFF 依赖。
/// </summary>
[Route("mgmt/v1/clients")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
public sealed partial class ManagementClientsController(
    PandaAuthDbContext dbContext,
    IOpenIddictApplicationManager applications,
    AdminAuditWriter audit,
    ManagementRateLimiter rateLimiter,
    ILogger<ManagementClientsController> logger) : ControllerBase
{
    internal const int MaxPageSize = 50;
    internal const int DefaultPageSize = 20;

    /// <summary>第一方/平台级客户端：管理 API 一律拒绝写入（与种子对账职责冲突）。</summary>
    private static readonly HashSet<string> ReservedClientIds = new(StringComparer.Ordinal)
    {
        "me-web", "admin-web", "mgmt-api", "fleet-api",
    };

    [HttpGet]
    [Authorize(Policy = MgmtApiAuthorization.ClientsReadPolicy)]
    public async Task<IActionResult> List(
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        CancellationToken cancellationToken)
    {
        if (RateGate(rateLimiter.CheckRead(ClientKey(), Ip())) is { } gate)
        {
            return gate;
        }

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

    [HttpGet("{clientId}")]
    [Authorize(Policy = MgmtApiAuthorization.ClientsReadPolicy)]
    public async Task<IActionResult> Detail(string clientId)
    {
        if (RateGate(rateLimiter.CheckRead(ClientKey(), Ip())) is { } gate)
        {
            return gate;
        }

        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        return Ok(await AdminClientsController.BuildDetailAsync(applications, application));
    }

    /// <summary>创建客户端：固定授权码 + 强制 PKCE + 刷新权限集（与站内客户端同构）；密钥明文仅本次响应返回一次。</summary>
    [HttpPost]
    [Authorize(Policy = MgmtApiAuthorization.ClientsWritePolicy)]
    public async Task<IActionResult> Create(
        [FromBody] ManagementCreateClientRequest? request,
        CancellationToken cancellationToken)
    {
        if (RateGate(rateLimiter.CheckSecret(ClientKey(), Ip())) is { } gate)
        {
            return gate;
        }

        if (request is null || string.IsNullOrWhiteSpace(request.DisplayName))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "请求体缺失或 displayName 为空");
        }

        var clientType = request.ClientType is null or "confidential" ? ClientTypes.Confidential
            : request.ClientType == "public" ? ClientTypes.Public
            : null;
        if (clientType is null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "clientType 非法",
                detail: "只接受 confidential（默认）或 public。");
        }

        var redirectUris = request.RedirectUris ?? [];
        if (redirectUris.Count == 0)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "回调白名单不能为空",
                detail: "没有回调地址的客户端无法完成授权码登录。");
        }

        var invalidUri = redirectUris.Concat(request.PostLogoutRedirectUris ?? [])
            .FirstOrDefault(uri => !IsAbsoluteHttpUri(uri));
        if (invalidUri is not null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "白名单包含非法地址",
                detail: $"{invalidUri} —— 必须是绝对的 http(s) URL。");
        }

        var clientId = request.ClientId;
        if (clientId is not null && !ClientIdPattern().IsMatch(clientId))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "clientId 非法",
                detail: "3–64 位 ASCII 字母/数字/._-（自定义 clientId 可省略，服务端生成）。");
        }

        if (clientId is null)
        {
            clientId = $"client-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}";
        }
        else if (ReservedClientIds.Contains(clientId) || await applications.FindByClientIdAsync(clientId) is not null)
        {
            return Problem(statusCode: StatusCodes.Status409Conflict, title: "clientId 已存在或为保留名");
        }

        var secret = clientType == ClientTypes.Confidential
            ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            : null;

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = clientType,
            ClientSecret = secret,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = request.DisplayName.Trim(),
        };
        foreach (var uri in redirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        foreach (var uri in request.PostLogoutRedirectUris ?? [])
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        // 固定权限集（与 demo-web 同构）：授权码 + 强制 PKCE + 刷新；scope 权限覆盖站内已注册标准 scope。
        descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(Permissions.Endpoints.Token);
        descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
        descriptor.Permissions.Add(Permissions.Endpoints.Revocation);
        descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
        descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
        descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
        descriptor.Permissions.Add(Permissions.Scopes.Email);
        descriptor.Permissions.Add(Permissions.Scopes.Profile);
        descriptor.Permissions.Add(Permissions.Scopes.Roles);
        descriptor.Permissions.Add(Permissions.Prefixes.Scope + Scopes.OfflineAccess);
        descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);

        await applications.CreateAsync(descriptor);

        var detail = await FindDetailAsync(clientId, cancellationToken);
        await audit.RecordAsync(
            AdminAuditing.Entry(User, "mgmt.client.create", "client", clientId,
                new { clientType = clientType, displayName = request.DisplayName.Trim() },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation("Management API 创建了客户端 {ClientId}（{ClientType}）。", clientId, clientType);

        return Ok(new ManagementCreateClientResponse(detail!, secret));
    }

    /// <summary>更新注册表字段：只覆盖请求中显式给出的字段（displayName / 回调 / 登出白名单）。</summary>
    [HttpPatch("{clientId}")]
    [Authorize(Policy = MgmtApiAuthorization.ClientsWritePolicy)]
    public async Task<IActionResult> Update(
        string clientId,
        [FromBody] ManagementUpdateClientRequest? request,
        CancellationToken cancellationToken)
    {
        if (RateGate(rateLimiter.CheckWrite(ClientKey(), Ip())) is { } gate)
        {
            return gate;
        }

        if (ReservedClientIds.Contains(clientId))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "保留客户端",
                detail: $"{clientId} 是第一方/平台客户端，对 Management API 只读。");
        }

        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        if (request is null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "请求体缺失");
        }

        var previousRedirect = (await applications.GetRedirectUrisAsync(application)).ToArray();
        var previousPostLogout = (await applications.GetPostLogoutRedirectUrisAsync(application)).ToArray();

        if (request.RedirectUris is { Count: 0 })
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "回调白名单不能为空",
                detail: "清空 RedirectUris 会让该客户端永远无法完成登录回调；如需停用请删除客户端。");
        }

        var invalidUri = (request.RedirectUris ?? []).Concat(request.PostLogoutRedirectUris ?? [])
            .FirstOrDefault(uri => !IsAbsoluteHttpUri(uri));
        if (invalidUri is not null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "白名单包含非法地址",
                detail: $"{invalidUri} —— 必须是绝对的 http(s) URL。");
        }

        var updated = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(updated, application);
        if (request.DisplayName is not null)
        {
            updated.DisplayName = string.IsNullOrWhiteSpace(request.DisplayName)
                ? updated.DisplayName
                : request.DisplayName.Trim();
        }

        if (request.RedirectUris is not null)
        {
            updated.RedirectUris.Clear();
            foreach (var uri in request.RedirectUris)
            {
                updated.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }
        }

        if (request.PostLogoutRedirectUris is not null)
        {
            updated.PostLogoutRedirectUris.Clear();
            foreach (var uri in request.PostLogoutRedirectUris)
            {
                updated.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }
        }

        await applications.PopulateAsync(application, updated);
        await applications.UpdateAsync(application);

        await audit.RecordAsync(
            AdminAuditing.Entry(User, "mgmt.client.update", "client", clientId,
                new
                {
                    displayName = request.DisplayName,
                    redirectUris = request.RedirectUris,
                    postLogoutRedirectUris = request.PostLogoutRedirectUris,
                    previousRedirectUris = previousRedirect,
                    previousPostLogoutRedirectUris = previousPostLogout,
                },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation("Management API 更新了客户端 {ClientId} 的注册表字段。", clientId);

        return Ok(await FindDetailAsync(clientId, cancellationToken));
    }

    /// <summary>重置密钥：生成 32 字节随机值，明文仅本次响应返回一次，库内只落哈希。</summary>
    [HttpPost("{clientId}/reset-secret")]
    [Authorize(Policy = MgmtApiAuthorization.ClientsWritePolicy)]
    public async Task<IActionResult> ResetSecret(string clientId, CancellationToken cancellationToken)
    {
        if (RateGate(rateLimiter.CheckSecret(ClientKey(), Ip())) is { } gate)
        {
            return gate;
        }

        if (ReservedClientIds.Contains(clientId))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "保留客户端",
                detail: $"{clientId} 是第一方/平台客户端，对 Management API 只读。");
        }

        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        if (!string.Equals(await applications.GetClientTypeAsync(application), ClientTypes.Confidential, StringComparison.Ordinal))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "非机密客户端",
                detail: "公共客户端（PKCE）没有密钥，无从重置。");
        }

        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        // 必须走 UpdateAsync(application, secret)：唯一会重新哈希的路径（DbSeeder 实证结论）。
        await applications.UpdateAsync(application, secret);

        await audit.RecordAsync(
            AdminAuditing.Entry(User, "mgmt.client.rotate_secret", "client", clientId,
                new { note = "secret rotated; plaintext returned once, not stored" },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation("Management API 重置了客户端 {ClientId} 的密钥。", clientId);

        return Ok(new AdminRotateSecretResponse(clientId, secret));
    }

    /// <summary>删除客户端（不可逆）：删除后该客户端的令牌经由在线校验即时失效。</summary>
    [HttpDelete("{clientId}")]
    [Authorize(Policy = MgmtApiAuthorization.ClientsWritePolicy)]
    public async Task<IActionResult> Delete(string clientId, CancellationToken cancellationToken)
    {
        if (RateGate(rateLimiter.CheckWrite(ClientKey(), Ip())) is { } gate)
        {
            return gate;
        }

        if (ReservedClientIds.Contains(clientId))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "保留客户端",
                detail: $"{clientId} 是第一方/平台客户端，对 Management API 只读。");
        }

        var application = await applications.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return NotFound();
        }

        await applications.DeleteAsync(application);

        await audit.RecordAsync(
            AdminAuditing.Entry(User, "mgmt.client.delete", "client", clientId,
                new { note = "client deleted" },
                HttpContext.Connection.RemoteIpAddress?.ToString()),
            cancellationToken);
        logger.LogInformation("Management API 删除了客户端 {ClientId}。", clientId);

        return NoContent();
    }

    /// <summary>限流门：Allowed 直接放行，被拒返回 429 + Retry-After。</summary>
    private IActionResult? RateGate(ManagementRateLimiter.Decision decision)
        => decision.Allowed ? null : this.TooManyRequests(decision);

    private string ClientKey() => ManagementRateLimiterPrincipals.GetClientId(User);

    private string? Ip() => HttpContext.Connection.RemoteIpAddress?.ToString();

    private async Task<AdminClientDetail?> FindDetailAsync(string clientId, CancellationToken cancellationToken)
    {
        var application = await applications.FindByClientIdAsync(clientId);
        return application is null ? null : await AdminClientsController.BuildDetailAsync(applications, application);
    }

    private static bool IsAbsoluteHttpUri(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    [GeneratedRegex(@"^[A-Za-z0-9._-]{3,64}$")]
    private static partial Regex ClientIdPattern();
}

public sealed record ManagementCreateClientRequest(
    string DisplayName,
    string? ClientType,
    string? ClientId,
    IReadOnlyList<string>? RedirectUris,
    IReadOnlyList<string>? PostLogoutRedirectUris);

public sealed record ManagementUpdateClientRequest(
    string? DisplayName,
    IReadOnlyList<string>? RedirectUris,
    IReadOnlyList<string>? PostLogoutRedirectUris);

public sealed record ManagementCreateClientResponse(AdminClientDetail Client, string? GeneratedSecret);
