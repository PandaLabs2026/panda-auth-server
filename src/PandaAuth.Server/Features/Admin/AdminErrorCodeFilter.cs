using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 为 Admin API 的 ProblemDetails 注入稳定错误码（extensions.code）：
/// 以 title → 码注册表匹配即注入，未登记的 title 保持无码，前端按未知码降级显示 detail。
/// 调用点零改动——title 是控制器里的字面量，登记于此即获得码
/// （ADR 2026-10-11-admin-error-codes：前端 t('server.'+code, {defaultValue: detail})）。
/// </summary>
/// <remarks>
/// 只在结果执行前改写 ObjectResult 的 ProblemDetails Value；已有 code 的不覆盖。
/// Claims 控制器的动态 title（服务返回的结构化错误码）不登记，自然走降级。
/// </remarks>
public sealed class AdminErrorCodeFilter : IActionFilter
{
    public static readonly IReadOnlyDictionary<string, string> CodeByTitle = new Dictionary<string, string>
    {
        // ---- AdminUsersController ----
        ["用户名不能为空"] = "user.name_required",
        ["建号失败"] = "user.create_failed",
        ["账号已创建但授予管理员角色失败"] = "user.create_role_grant_failed",
        ["无效的状态变更"] = "user.status_invalid",
        ["不能变更自己的账号状态"] = "user.self_status_forbidden",
        ["状态更新失败"] = "user.status_update_failed",
        ["不能重置自己的密码"] = "user.self_password_reset_forbidden",
        ["新密码不合规"] = "user.password_invalid",
        ["无效的角色集合"] = "user.roles_invalid",
        ["未知角色"] = "user.role_unknown",
        ["不能移除自己的管理员角色"] = "user.self_role_removal_forbidden",
        ["角色变更部分失败"] = "user.roles_partial_failure",
        ["解除锁定失败"] = "user.unlock_failed",
        ["重置失败计数失败"] = "user.unlock_count_reset_failed",
        ["不能对自己执行踢下线"] = "user.self_revoke_forbidden",
        ["无效的资料变更"] = "user.profile_invalid",
        ["资料更新失败"] = "user.profile_update_failed",
        ["确认用户名不匹配"] = "user.deactivate_confirm_mismatch",
        ["不能注销自己的账号"] = "user.self_deactivate_forbidden",
        ["注销失败"] = "user.deactivate_failed",
        ["账号已注销"] = "user.deleted",
        // ---- AdminClientsController / AdminClaimsController（共用请求体缺失） ----
        ["请求体缺失"] = "common.body_missing",
        ["回调白名单不能为空"] = "client.redirect_uris_required",
        ["白名单包含非法地址"] = "client.redirect_uri_invalid",
        ["权限集不能为空"] = "client.permissions_required",
        ["包含未知权限"] = "client.permission_unknown",
        ["非机密客户端"] = "client.not_confidential",
    };

    public void OnActionExecuting(ActionExecutingContext context) { }

    public void OnActionExecuted(ActionExecutedContext context)
    {
        if (context.Result is not ObjectResult { Value: ProblemDetails problem }) return;
        if (problem.Extensions.ContainsKey("code")) return;
        if (problem.Title is not { } title || !CodeByTitle.TryGetValue(title, out var code)) return;
        problem.Extensions["code"] = code;
    }
}
