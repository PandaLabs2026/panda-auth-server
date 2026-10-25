using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

/// <summary>操作注册表：签发与消费两端共用的唯一口径，端点不得自带游离字面量。</summary>
public static class MfaOperations
{
    // ---- 管理域（Admin API）----
    public const string AdminUpdateRoles = "admin.users.update-roles";
    public const string AdminSetStatus = "admin.users.set-status";
    public const string AdminResetTwoFactor = "admin.users.reset-2fa";
    public const string AdminDeactivate = "admin.users.deactivate";
    public const string AdminUpdateRedirectUris = "admin.clients.update-redirect-uris";
    public const string AdminUpdatePermissions = "admin.clients.update-permissions";
    public const string AdminRotateSecret = "admin.clients.rotate-secret";
    public const string AdminAddUserClaim = "admin.claims.add-user-claim";
    public const string AdminRemoveUserClaim = "admin.claims.remove-user-claim";
    public const string AdminAddRoleClaim = "admin.claims.add-role-claim";
    public const string AdminRemoveRoleClaim = "admin.claims.remove-role-claim";

    // ---- 用户自助域（me 安全设置）----
    public const string SelfTotpEnroll = "self.totp-enroll";
    public const string SelfRevokeFactor = "self.revoke-factor";
    public const string SelfRecoveryCodes = "self.recovery-codes";

    private static readonly HashSet<string> All =
    [
        AdminUpdateRoles, AdminSetStatus, AdminResetTwoFactor, AdminDeactivate,
        AdminUpdateRedirectUris, AdminUpdatePermissions, AdminRotateSecret,
        AdminAddUserClaim, AdminRemoveUserClaim, AdminAddRoleClaim, AdminRemoveRoleClaim,
        SelfTotpEnroll, SelfRevokeFactor, SelfRecoveryCodes,
    ];

    /// <summary>特敏感操作：权限提升与自身 MFA/恢复方式变更，签发时须再核验操作者当前密码。</summary>
    private static readonly HashSet<string> PasswordRequiredOperations =
    [
        AdminUpdateRoles, AdminAddUserClaim, AdminRemoveUserClaim, AdminAddRoleClaim, AdminRemoveRoleClaim,
        SelfTotpEnroll, SelfRevokeFactor, SelfRecoveryCodes,
    ];

    public static bool IsValid(string operation) => All.Contains(operation);

    public static bool RequiresPassword(string operation) => PasswordRequiredOperations.Contains(operation);
}

/// <summary>签发失败原因（不承载任何敏感值，可直接映射为用户可见文案或审计字段）。</summary>
public enum MfaGrantIssueError
{
    None,
    UnknownOperation,
    TotpNotBound,
    InvalidCode,
    PasswordRequired,
    PasswordRejected,
}

public sealed record MfaGrantIssued(Guid GrantId, DateTimeOffset ExpiresAt);

/// <summary>
/// 操作绑定的 TOTP 授权（AUTH-DELIVERY-002，Passkey 退役后的高风险操作门禁）：
/// 一次 TOTP 验证（+特敏感操作的操作者密码核验）只授权一次明确操作。授权行落在
/// panda_mfa_challenges（复用 WebAuthn ceremony 的既有存储与原子消费模式），
/// Purpose=op-grant:&lt;operation&gt;，Value 绑定目标、关键参数哈希与签发时的账号安全版本；
/// 5 分钟有效、单次消费。修改参数、换目标、过期、重放或账号安全版本变化均无法继续使用。
/// </summary>
public sealed class MfaOperationGrantService(
    MfaChallengeStore challenges,
    TotpFactorService totpFactors,
    PandaAuthDbContext db,
    UserService users,
    IPasswordHasher passwordHasher,
    TimeProvider clock)
{
    public static readonly TimeSpan GrantLifetime = TimeSpan.FromMinutes(5);

    public static string PurposeOf(string operation) => $"op-grant:{operation}";

    /// <summary>
    /// 关键参数规范化哈希：键按 Ordinal 排序后序列化为 JSON 再取 SHA-256，
    /// 保证签发与消费两端对同一参数集合得到相同摘要（与参数出现顺序无关）。
    /// </summary>
    public static string HashParameters(IReadOnlyDictionary<string, string?>? parameters)
    {
        var canonical = parameters is null || parameters.Count == 0
            ? "{}"
            : JsonSerializer.Serialize(new SortedDictionary<string, string?>(new Dictionary<string, string?>(parameters), StringComparer.Ordinal));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    /// <summary>
    /// 签发：验证操作者已绑定 TOTP → 验证 TOTP 码（LastAcceptedTimeStep 防重放，
    /// 同一码不得反复签发授权）→ 特敏感操作核验操作者本人当前密码（绝不触碰被管理用户的密码）
    /// → 落授权行。任何失败不产生授权行。
    /// </summary>
    public async Task<(MfaGrantIssued? Issued, MfaGrantIssueError Error)> IssueAsync(
        string operatorId,
        string operation,
        string targetId,
        IReadOnlyDictionary<string, string?>? parameters,
        string totpCode,
        string? currentPassword,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operatorId);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetId);
        if (!MfaOperations.IsValid(operation)) return (null, MfaGrantIssueError.UnknownOperation);

        var user = await users.FindByIdAsync(operatorId);
        if (user is null) return (null, MfaGrantIssueError.TotpNotBound);

        var totpBound = await db.TotpFactors.AnyAsync(
            factor => factor.UserId == operatorId && factor.RevokedAt == null && factor.ConfirmedAt != null,
            cancellationToken);
        if (!totpBound) return (null, MfaGrantIssueError.TotpNotBound);

        if (string.IsNullOrWhiteSpace(totpCode) ||
            !await totpFactors.VerifyAsync(operatorId, totpCode.Trim(), cancellationToken))
        {
            return (null, MfaGrantIssueError.InvalidCode);
        }

        if (MfaOperations.RequiresPassword(operation))
        {
            if (string.IsNullOrEmpty(currentPassword)) return (null, MfaGrantIssueError.PasswordRequired);
            if (string.IsNullOrEmpty(user.PasswordHash)) return (null, MfaGrantIssueError.PasswordRejected);
            // 与登录路径同一 Argon2id 哈希器（IPasswordHasher）；SuccessRehashNeeded 同样放行，
            // 哈希参数升级由正常改密路径完成，不在授权签发里顺带改写。
            var outcome = passwordHasher.Verify(user.PasswordHash, currentPassword);
            if (outcome == PasswordVerificationOutcome.Failed) return (null, MfaGrantIssueError.PasswordRejected);
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(new OperationGrantPayload(
            targetId,
            HashParameters(parameters),
            AccountSecurityVersion.From(user)));
        var grantId = await challenges.CreateAsync(
            PurposeOf(operation), operatorId, payload, GrantLifetime, cancellationToken);
        return (new MfaGrantIssued(grantId, clock.GetUtcNow().Add(GrantLifetime)), MfaGrantIssueError.None);
    }

    /// <summary>
    /// 消费：先按 purpose+操作者原子占位（天然单次：任何后续重放直接失败），
    /// 再核对目标、参数哈希与账号安全版本（当前值取自数据库而非令牌——角色/因子/安全戳
    /// 变化后即使令牌尚未过期，旧授权也立即不可用）。任一不符即拒绝，授权行已烧毁。
    /// </summary>
    public async Task<bool> ConsumeAsync(
        string operatorId,
        Guid grantId,
        string operation,
        string targetId,
        IReadOnlyDictionary<string, string?>? parameters,
        CancellationToken cancellationToken)
    {
        var consumed = await challenges.ConsumeAsync(grantId, PurposeOf(operation), operatorId, cancellationToken);
        if (consumed is null) return false;

        OperationGrantPayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<OperationGrantPayload>(consumed.Value);
        }
        catch (JsonException)
        {
            return false;
        }
        if (payload is null ||
            !string.Equals(payload.TargetId, targetId, StringComparison.Ordinal) ||
            !string.Equals(payload.ParamsHash, HashParameters(parameters), StringComparison.Ordinal))
        {
            return false;
        }

        var user = await users.FindByIdAsync(operatorId);
        return user is not null && string.Equals(payload.SecurityVersion, CurrentSecurityVersion(user), StringComparison.Ordinal);
    }

    private static string CurrentSecurityVersion(PandaUser? user)
        => user is null ? string.Empty : AccountSecurityVersion.From(user);
}

internal sealed record OperationGrantPayload(string TargetId, string ParamsHash, string SecurityVersion);
