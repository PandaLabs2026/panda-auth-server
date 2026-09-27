using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Management;

/// <summary>
/// Management API（M0）作用域门禁：audience + scope 双条件。
/// scope 与 audience 的单一事实源在 share 的 <see cref="PandaAuthMgmtApi"/>（公开契约）。
/// M2M 主体无用户角色、无 MFA step-up（那是对人的门禁）；替代控制是最小化 scope、
/// 专用机密客户端、部署面总开关、速率限制与写审计（设计稿：元仓 2026-09-27-management-api-m0-design.md）。
/// </summary>
internal static class MgmtApiAuthorization
{
    /// <summary>资源指示器：mgmt.* scope 实体绑定该 audience，令牌缺此 audience 一律拒绝（防跨资源重放）。</summary>
    public const string Audience = PandaAuthMgmtApi.Audience;

    public const string ClientsReadPolicy = "mgmt-clients-read";
    public const string ClientsWritePolicy = "mgmt-clients-write";
    public const string UsersReadPolicy = "mgmt-users-read";

    public const string ClientsReadScope = PandaAuthMgmtApi.ClientsReadScope;
    public const string ClientsWriteScope = PandaAuthMgmtApi.ClientsWriteScope;
    public const string UsersReadScope = PandaAuthMgmtApi.UsersReadScope;

    /// <summary>audience 与 scope 缺一不可；两者都兼容两种载体（见下）。</summary>
    public static bool HasAudienceAndScope(ClaimsPrincipal principal, string scope)
        => HasAudience(principal) && HasScope(principal, scope);

    /// <summary>
    /// audience 双载体：OpenIddict 私有 <c>oi_aud</c>（验证管线富化路径）或标准 <c>aud</c> claim
    /// （自包含 JWT/JWE 直接解出的路径）。只读其一会在另一种令牌路径上漏判。
    /// </summary>
    private static bool HasAudience(ClaimsPrincipal principal)
        => principal.GetAudiences().Contains(Audience, StringComparer.Ordinal)
           || principal.FindAll(OpenIddictConstants.Claims.Audience)
               .Any(claim => string.Equals(claim.Value, Audience, StringComparison.Ordinal));

    /// <summary>scope 双载体：私有 <c>oi_scp</c>（<see cref="OpenIddict.Abstractions.PrincipalExtensions.HasScope"/>）或标准 scope claim（单值空格分隔或多 claim）。</summary>
    private static bool HasScope(ClaimsPrincipal principal, string scope)
        => principal.HasScope(scope)
           || principal.FindAll(OpenIddictConstants.Claims.Scope)
               .Any(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                   .Contains(scope, StringComparer.Ordinal));

    public static Action<AuthorizationPolicyBuilder> RequireScope(string scope)
    {
        return policy => policy.RequireAssertion(context => HasAudienceAndScope(context.User, scope));
    }
}
