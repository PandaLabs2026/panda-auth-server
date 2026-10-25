using Microsoft.AspNetCore.Mvc;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

/// <summary>
/// 受保护端点的授权消费门：请求头 X-Panda-Mfa-Grant 携带授权 id。
/// 缺头 → 403 + X-Panda-Mfa-Grant-Required 标记（前端据此弹 TOTP 授权对话框）；
/// 授权无效/过期/重放/换目标/换参数/安全版本变化 → 403 mfaGrantRejected（授权行已烧毁，须重新签发）。
/// 响应体回显 operation/targetId/parameters/passwordRequired，前端原样用于签发请求，避免两端参数口径漂移。
/// </summary>
public static class MfaOperationGrantGate
{
    public const string GrantHeader = "X-Panda-Mfa-Grant";
    public const string GrantRequiredHeader = "X-Panda-Mfa-Grant-Required";

    /// <summary>签发端点共用的失败映射（管理域与用户自助域同一口径）。</summary>
    public static ObjectResult IssueError(MfaGrantIssueError error) => error switch
    {
        MfaGrantIssueError.UnknownOperation => new BadRequestObjectResult(new { error = "未知操作类型。" }),
        MfaGrantIssueError.TotpNotBound => new ObjectResult(
            new { totpEnrollmentRequired = true, error = "请先绑定 TOTP 验证器。" }) { StatusCode = StatusCodes.Status403Forbidden },
        MfaGrantIssueError.InvalidCode => new BadRequestObjectResult(new { error = "验证码错误、已过期或已被使用。" }),
        MfaGrantIssueError.PasswordRequired => new BadRequestObjectResult(new { error = "该操作需要同时验证当前密码。" }),
        MfaGrantIssueError.PasswordRejected => new BadRequestObjectResult(new { error = "当前密码不正确。" }),
        _ => new BadRequestObjectResult(new { error = "授权签发失败。" }),
    };

    public static async Task<IActionResult?> ConsumeAsync(
        Controller controller,
        MfaOperationGrantService grants,
        SecurityEventWriter? securityEvents,
        string operatorId,
        string operation,
        string targetId,
        IReadOnlyDictionary<string, string?>? parameters,
        CancellationToken cancellationToken)
    {
        var headerValue = controller.Request.Headers[GrantHeader].ToString();
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            controller.Response.Headers[GrantRequiredHeader] = "true";
            return new ObjectResult(new
            {
                mfaGrantRequired = true,
                operation,
                targetId,
                parameters = Canonical(parameters),
                passwordRequired = MfaOperations.RequiresPassword(operation),
            })
            { StatusCode = StatusCodes.Status403Forbidden };
        }

        var valid = Guid.TryParse(headerValue, out var grantId) && await grants.ConsumeAsync(
            operatorId, grantId, operation, targetId, parameters, cancellationToken);
        if (valid)
        {
            await RecordAsync(securityEvents, controller, "mfa.grant_consumed", operatorId, operation, targetId, null, cancellationToken);
            return null;
        }

        await RecordAsync(securityEvents, controller, "mfa.grant_rejected", operatorId, operation, targetId,
            new { reason = "invalid_or_expired" }, cancellationToken);
        return new ObjectResult(new { mfaGrantRejected = true, error = "操作授权无效或已过期，请重新验证。" })
        { StatusCode = StatusCodes.Status403Forbidden };
    }

    private static IReadOnlyDictionary<string, string?> Canonical(IReadOnlyDictionary<string, string?>? parameters)
        => parameters is null ? [] : new SortedDictionary<string, string?>(new Dictionary<string, string?>(parameters), StringComparer.Ordinal);

    private static Task RecordAsync(
        SecurityEventWriter? securityEvents,
        Controller controller,
        string eventType,
        string operatorId,
        string operation,
        string targetId,
        object? metadata,
        CancellationToken cancellationToken)
        => securityEvents is null
            ? Task.CompletedTask
            : securityEvents.RecordAsync(new SecurityEventEntry(
                eventType,
                operatorId,
                operatorId,
                "mfa_grant",
                targetId,
                MfaClaimTypes.Totp,
                new { operation, targetId, detail = metadata },
                controller.HttpContext.Connection.RemoteIpAddress?.ToString(),
                controller.Request.Headers.UserAgent.ToString(),
                controller.HttpContext.TraceIdentifier), cancellationToken);
}
