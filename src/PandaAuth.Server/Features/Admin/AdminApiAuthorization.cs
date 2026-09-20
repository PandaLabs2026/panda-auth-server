namespace PandaAuth.Server.Features.Admin;

/// <summary>Admin 数据 API 的授权约定（策略名），控制器特性与 Program.cs 注册处共用。</summary>
internal static class AdminApiAuthorization
{
    /// <summary>Bearer（OpenIddict Validation 方案）+ admin 角色（按 claim 短名断言，见 Program.cs 注册处注释）。</summary>
    public const string PolicyName = "admin-api";

    /// <summary>不可逆或权限扩大操作必须由五分钟内的 Passkey 验证确认，TOTP 不能替代。</summary>
    public static bool HasRecentWebAuthn(System.Security.Claims.ClaimsPrincipal principal)
        => Infrastructure.Security.Mfa.RecentMfaRequirement.HasRecentWebAuthn(principal, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
}
