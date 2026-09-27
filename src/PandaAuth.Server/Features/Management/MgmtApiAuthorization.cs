using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;

namespace PandaAuth.Server.Features.Management;

/// <summary>
/// Management API（M0）作用域门禁：audience + scope 双条件。
/// M2M 主体无用户角色、无 MFA step-up（那是对人的门禁）；替代控制是最小化 scope、
/// 专用机密客户端、部署面总开关、速率限制与写审计（设计稿：元仓 2026-09-27-management-api-m0-design.md）。
/// </summary>
internal static class MgmtApiAuthorization
{
    /// <summary>资源指示器：mgmt.* scope 实体绑定该 audience，令牌缺此 audience 一律拒绝（防跨资源重放）。</summary>
    public const string Audience = "panda-mgmt-api";

    public const string ClientsReadPolicy = "mgmt-clients-read";
    public const string ClientsWritePolicy = "mgmt-clients-write";
    public const string UsersReadPolicy = "mgmt-users-read";

    public const string ClientsReadScope = "mgmt.clients.read";
    public const string ClientsWriteScope = "mgmt.clients.write";
    public const string UsersReadScope = "mgmt.users.read";

    /// <summary>audience 与 scope 缺一不可：只带 scope 的令牌可能是为其他资源签发的。</summary>
    public static bool HasAudienceAndScope(ClaimsPrincipal principal, string scope)
        => principal.GetAudiences().Contains(Audience, StringComparer.Ordinal)
           && principal.HasScope(scope);

    public static Action<AuthorizationPolicyBuilder> RequireScope(string scope)
    {
        return policy => policy.RequireAssertion(context => HasAudienceAndScope(context.User, scope));
    }
}
