using System.Security.Claims;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public sealed class MfaPolicyException(string message) : InvalidOperationException(message);

public sealed record MfaStatus(
    bool HasActiveFactor,
    bool RequiresReconfiguration,
    int RecoveryCodeCount);

public sealed record MfaFactorInfo(
    Guid Id,
    string Type,
    string? FriendlyName,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt);

public sealed class MfaService(
    PandaAuthDbContext db,
    UserService users,
    TotpFactorService totpFactors,
    LoginSessionService sessions,
    TimeProvider clock)
{
    private readonly LoginSessionService _sessions = sessions;
    private const int RecoveryCodeCount = 10;

    public async Task<TotpEnrollment> BeginEnrollmentAsync(
        string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        await RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);
        return await totpFactors.BeginEnrollmentAsync(userId, cancellationToken);
    }

    public Task RequireEnrollmentAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
        => RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);

    public async Task<bool> ConfirmLegacyReconfigurationAsync(
        string userId, Guid factorId, string code, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId) ?? throw new MfaPolicyException("User not found.");
        if (!user.TwoFactorEnabled) throw new MfaPolicyException("MFA reconfiguration is not required.");
        if (!user.EmailConfirmed) throw new MfaPolicyException("Email confirmation is required.");
        if (!await totpFactors.ConfirmAsync(userId, factorId, code, cancellationToken)) return false;
        user.TwoFactorEnabled = false;
        var result = await users.UpdateAsync(user);
        if (!result.Succeeded) throw new MfaPolicyException("MFA reconfiguration could not be completed.");
        return true;
    }

    public async Task<bool> ConfirmEnrollmentAsync(
        string userId, ClaimsPrincipal principal, Guid factorId, string code, CancellationToken cancellationToken)
    {
        await RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);
        var confirmed = await totpFactors.ConfirmAsync(userId, factorId, code, cancellationToken);
        if (!confirmed) return false;
        // 轮换收口：新因子确认成功即撤销其余确认因子——换绑全程旧因子保持可用，
        // 不存在无因子窗口；到达此处的路径都已验证现有因子（self.totp-enroll 授权
        // 要求 TOTP+密码），恢复码不作废（比原撤销路径的 amr 窗验证更强）。
        var superseded = await db.TotpFactors
            .Where(item => item.UserId == userId && item.RevokedAt == null && item.ConfirmedAt != null && item.Id != factorId)
            .ToListAsync(cancellationToken);
        foreach (var stale in superseded)
            stale.RevokedAt = clock.GetUtcNow();
        if (superseded.Count > 0) await db.SaveChangesAsync(cancellationToken);
        var user = await users.FindByIdAsync(userId);
        if (user is not null && user.TwoFactorEnabled)
        {
            user.TwoFactorEnabled = false;
            await users.UpdateAsync(user);
        }
        return true;
    }

    public Task<bool> VerifyAsync(string userId, string code, CancellationToken cancellationToken)
        => totpFactors.VerifyAsync(userId, code, cancellationToken);

    public async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(
        string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        await RequireEnrollmentPolicyAsync(userId, principal, cancellationToken);
        var old = await db.MfaRecoveryCodes.Where(x => x.UserId == userId && x.ConsumedAt == null).ToListAsync(cancellationToken);
        db.MfaRecoveryCodes.RemoveRange(old);
        var codes = new List<string>(RecoveryCodeCount);
        for (var i = 0; i < RecoveryCodeCount; i++)
        {
            var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            var salt = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            db.MfaRecoveryCodes.Add(new MfaRecoveryCode
            {
                UserId = userId,
                CodeHash = HashRecoveryCode(salt, code),
                Salt = salt,
                CreatedAt = clock.GetUtcNow()
            });
            codes.Add(code);
        }
        await db.SaveChangesAsync(cancellationToken);
        return codes;
    }

    public async Task<bool> ConsumeRecoveryCodeAsync(string userId, string code, CancellationToken cancellationToken)
    {
        var candidates = await db.MfaRecoveryCodes
            .Where(x => x.UserId == userId && x.ConsumedAt == null)
            .ToListAsync(cancellationToken);
        foreach (var candidate in candidates)
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(candidate.CodeHash), Convert.FromHexString(HashRecoveryCode(candidate.Salt, code))))
                continue;
            var consumedAt = clock.GetUtcNow();
            if (db.Database.IsRelational())
            {
                var updated = await db.Database.ExecuteSqlInterpolatedAsync($"""
                    UPDATE panda_mfa_recovery_codes SET "ConsumedAt" = {consumedAt}
                    WHERE "Id" = {candidate.Id} AND "ConsumedAt" IS NULL
                    """, cancellationToken);
                db.ChangeTracker.Clear();
                return updated == 1;
            }
            candidate.ConsumedAt = consumedAt;
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        return false;
    }

    public async Task RevokeFactorAsync(string userId, Guid factorId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        await RequireRecentAuthenticationAsync(userId, principal, cancellationToken);
        await using var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            : null;
        var totp = await db.TotpFactors.SingleOrDefaultAsync(x => x.Id == factorId && x.UserId == userId && x.RevokedAt == null, cancellationToken);
        if (totp is not null)
        {
            // Passkey 已退役（AUTH-DELIVERY-002）：可验证因子口径下唯一 TOTP 不得自撤——
            // 换绑路径是「先加新 TOTP 再撤旧的」，这里守护最后一个可验证因子。
            var confirmedTotp = await db.TotpFactors.CountAsync(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null, cancellationToken);
            if (confirmedTotp <= 1)
                throw new MfaPolicyException("Cannot remove the last active factor.");
            totp.RevokedAt = clock.GetUtcNow();
            await RemoveRecoveryCodesAsync(userId, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            if (transaction is not null) await transaction.CommitAsync(cancellationToken);
            return;
        }
        throw new MfaPolicyException("Factor not found.");
    }

    public async Task<MfaStatus> GetStatusAsync(string userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId) ?? throw new MfaPolicyException("User not found.");
        var totp = await db.TotpFactors.AnyAsync(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null, cancellationToken);
        var recovery = await db.MfaRecoveryCodes.CountAsync(x => x.UserId == userId && x.ConsumedAt == null, cancellationToken);
        // 唯一可验证因子=已确认 TOTP（AUTH-DELIVERY-002；表已随删表批移除）。
        return new MfaStatus(totp, user.TwoFactorEnabled && !totp, recovery);
    }

    /// <summary>自助管理的因子清单（撤销所需的 factorId 来源）。</summary>
    public async Task<IReadOnlyList<MfaFactorInfo>> ListFactorsAsync(string userId, CancellationToken cancellationToken)
    {
        var totp = await db.TotpFactors
            .Where(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null)
            .OrderBy(x => x.CreatedAt)
            .Select(x => new MfaFactorInfo(x.Id, "totp", null, x.CreatedAt, null))
            .ToListAsync(cancellationToken);
        return totp;
    }

    private async Task RequireEnrollmentPolicyAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId) ?? throw new MfaPolicyException("User not found.");
        if (!user.EmailConfirmed) throw new MfaPolicyException("Email confirmation is required.");
        await RequireRecentAuthenticationAsync(userId, principal, cancellationToken);
    }

    /// <summary>近期认证窗口：所有自助 MFA 操作共用。</summary>
    private static readonly TimeSpan RecentAuthenticationWindow = TimeSpan.FromMinutes(5);

    private async Task RequireRecentAuthenticationAsync(string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        if (principal.FindFirstValue(ClaimTypes.NameIdentifier) != userId)
            throw new MfaPolicyException("Recent authentication is required.");
        var now = clock.GetUtcNow();
        if (RecentMfaRequirement.HasValidMfa(principal, now, RecentAuthenticationWindow))
            return;
        // 首因子解锁：amr 只能来自已完成的 MFA，账户没有任何活跃因子时不存在合法途径产生它，
        // 此时以 5 分钟内的密码登录（panda_authenticated_at）视为「近期重新认证」；
        // 已有因子后仍必须完成一次 MFA（防止仅凭密码注册第二因子绕过 step-up）。
        //
        // 管理员重置 MFA 之后，重置前签发的密码会话不得再用首因子解锁重建因子；否则
        // “重置 MFA”会被一个仍持有旧会话的人原地撤销。重置后重新登录（auth_time 晚于
        // 重置事件）才可按首因子流程重新绑定——这是本批选定的恢复口径，带外一次性
        // 再注册令牌是更强但更重的后续方案。
        if (!await HasVerifiableFactorAsync(userId, cancellationToken) &&
            SessionSecurityService.HasRecentAuthentication(principal, now, RecentAuthenticationWindow) &&
            !await WasResetAfterAuthenticationAsync(userId, principal, cancellationToken))
            return;
        throw new MfaPolicyException("Recent MFA authentication is required.");
    }

    /// <summary>最近一次管理员 MFA 重置是否晚于当前登录时刻；无法读取认证时刻时按“是”处理。</summary>
    private async Task<bool> WasResetAfterAuthenticationAsync(
        string userId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        if (!SessionSecurityService.TryGetAuthenticationTime(principal, out var authenticatedAt))
            return true;
        return await db.MfaRecoveryEvents.AnyAsync(evt =>
            evt.TargetUserId == userId &&
            evt.Reason == MfaRecoveryEvent.AdminResetReason &&
            evt.CreatedAt >= authenticatedAt,
            cancellationToken);
    }

    /// <summary>因子撤销后恢复码整体作废：旧码不得继续提供 step-up 事实。</summary>
    private async Task RemoveRecoveryCodesAsync(string userId, CancellationToken cancellationToken)
    {
        var codes = await db.MfaRecoveryCodes
            .Where(code => code.UserId == userId)
            .ToListAsync(cancellationToken);
        db.MfaRecoveryCodes.RemoveRange(codes);
    }

    /// <summary>
    /// 是否存在可验证因子（已确认 TOTP）——登录路径 MFA 挑战与首因子解锁的判定依据。
    /// Passkey 退役后不再计入：退役 passkey 无法产生任何合法验证事实，
    /// 仅剩退役 passkey 的账号按「无可验证因子」对待（密码登录即可重建首个 TOTP，全程审计）。
    /// </summary>
    public async Task<bool> HasVerifiableFactorAsync(string userId, CancellationToken cancellationToken)
        => await db.TotpFactors.AnyAsync(x => x.UserId == userId && x.RevokedAt == null && x.ConfirmedAt != null, cancellationToken);

    /// <summary>是否存在未消费恢复码——登录挑战页自救通道的可用性判定。</summary>
    public async Task<bool> HasRecoveryCodesAsync(string userId, CancellationToken cancellationToken)
        => await db.MfaRecoveryCodes.AnyAsync(x => x.UserId == userId && x.ConsumedAt == null, cancellationToken);

    private static string HashRecoveryCode(string salt, string code)
        => Convert.ToHexString(Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(salt + ":" + code),
            Encoding.UTF8.GetBytes(salt),
            100_000,
            HashAlgorithmName.SHA256,
            32)).ToLowerInvariant();
}
