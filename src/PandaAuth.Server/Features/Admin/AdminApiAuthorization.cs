namespace PandaAuth.Server.Features.Admin;

/// <summary>Admin 数据 API 的授权约定（策略名），控制器特性与 Program.cs 注册处共用。</summary>
internal static class AdminApiAuthorization
{
    /// <summary>Bearer（OpenIddict Validation 方案）+ admin 角色（按 claim 短名断言，见 Program.cs 注册处注释）。</summary>
    public const string PolicyName = "admin-api";
}
