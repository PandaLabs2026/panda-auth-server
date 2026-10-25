using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// 操作授权全矩阵（AUTH-DELIVERY-002，替代 Passkey 五分钟窗）：
/// 签发（TOTP 防重放/密码核验/未绑定拒绝）与消费（单次/绑定目标与参数/安全版本/过期）。
/// </summary>
public class MfaOperationGrantTests
{
    [Fact]
    public async Task Issue_WithValidTotpAndPassword_Succeeds_AndReplayOfSameCodeIsRejected()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var grants = TestGrants.Create(provider);
        var parameters = new Dictionary<string, string?> { ["roles"] = "admin,member" };

        var (issued, error) = await grants.IssueAsync(user.Id, MfaOperations.AdminUpdateRoles, "user-2",
            parameters, TotpCode(secret), "Strong!Pass123", CancellationToken.None);
        Assert.Equal(MfaGrantIssueError.None, error);
        Assert.NotNull(issued);

        // TOTP timestep 已被消费：同一验证码不得反复签发授权（防重放）。
        var (replayed, replayError) = await grants.IssueAsync(user.Id, MfaOperations.AdminUpdateRoles, "user-2",
            parameters, TotpCode(secret), "Strong!Pass123", CancellationToken.None);
        Assert.Equal(MfaGrantIssueError.InvalidCode, replayError);
        Assert.Null(replayed);
    }

    [Fact]
    public async Task Issue_WrongPassword_RejectedWithoutGrantRow()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var grants = TestGrants.Create(provider);

        var (issued, error) = await grants.IssueAsync(user.Id, MfaOperations.AdminUpdateRoles, "user-2",
            null, TotpCode(secret), "Wrong!Pass456", CancellationToken.None);

        Assert.Equal(MfaGrantIssueError.PasswordRejected, error);
        Assert.Null(issued);
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().MfaChallenges);
    }

    [Fact]
    public async Task Issue_MissingPassword_ForPasswordOperation_IsRejected()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var grants = TestGrants.Create(provider);

        var (issued, error) = await grants.IssueAsync(user.Id, MfaOperations.AdminUpdateRoles, "user-2",
            null, TotpCode(secret), null, CancellationToken.None);

        Assert.Equal(MfaGrantIssueError.PasswordRequired, error);
        Assert.Null(issued);
    }

    [Fact]
    public async Task Issue_WithoutTotpBound_Rejected()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "no-totp", EmailConfirmed = true };
        await users.CreateAsync(user, "Strong!Pass123");
        var grants = TestGrants.Create(provider);

        var (issued, error) = await grants.IssueAsync(user.Id, MfaOperations.AdminSetStatus, "user-2",
            null, "123456", null, CancellationToken.None);

        Assert.Equal(MfaGrantIssueError.TotpNotBound, error);
        Assert.Null(issued);
    }

    [Fact]
    public async Task Issue_UnknownOperation_Rejected()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var grants = TestGrants.Create(provider);

        var (issued, error) = await grants.IssueAsync(user.Id, "admin.nope", "user-2",
            null, TotpCode(secret), null, CancellationToken.None);

        Assert.Equal(MfaGrantIssueError.UnknownOperation, error);
        Assert.Null(issued);
    }

    [Fact]
    public async Task Consume_ValidBinding_Succeeds_AndSecondConsumeFails()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var grants = TestGrants.Create(provider);
        var parameters = new Dictionary<string, string?> { ["status"] = "Frozen" };
        var (issued, _) = await grants.IssueAsync(user.Id, MfaOperations.AdminSetStatus, "user-9",
            parameters, TotpCode(secret), null, CancellationToken.None);

        // 参数顺序无关：同一集合不同顺序仍视为同一授权参数。
        var shuffled = new Dictionary<string, string?> { ["status"] = "Frozen" };
        Assert.True(await grants.ConsumeAsync(user.Id, issued!.GrantId, MfaOperations.AdminSetStatus, "user-9",
            shuffled, CancellationToken.None));
        // 单次使用：重放（含原序参数）一律失败。
        Assert.False(await grants.ConsumeAsync(user.Id, issued.GrantId, MfaOperations.AdminSetStatus, "user-9",
            parameters, CancellationToken.None));
    }

    [Fact]
    public async Task Consume_WrongTargetOrParams_Fails_AndBurnsTheGrant()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var grants = TestGrants.Create(provider);
        var parameters = new Dictionary<string, string?> { ["permissions"] = "a\nb" };
        var (issued, _) = await grants.IssueAsync(user.Id, MfaOperations.AdminUpdatePermissions, "client-1",
            parameters, TotpCode(secret), null, CancellationToken.None);

        // 换目标：拒绝。
        Assert.False(await grants.ConsumeAsync(user.Id, issued!.GrantId, MfaOperations.AdminUpdatePermissions, "client-2",
            parameters, CancellationToken.None));
        // 换参数：拒绝（且授权已在首次失败尝试中烧毁——改回正确参数也不可用）。
        var tampered = new Dictionary<string, string?> { ["permissions"] = "a\nb\nevil" };
        Assert.False(await grants.ConsumeAsync(user.Id, issued.GrantId, MfaOperations.AdminUpdatePermissions, "client-1",
            tampered, CancellationToken.None));
        Assert.False(await grants.ConsumeAsync(user.Id, issued.GrantId, MfaOperations.AdminUpdatePermissions, "client-1",
            parameters, CancellationToken.None));
    }

    [Fact]
    public async Task Consume_ByAnotherOperator_Fails()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var other = new PandaUser { UserName = "other-admin", EmailConfirmed = true };
        await provider.GetRequiredService<UserService>().CreateAsync(other, "Strong!Pass123");
        var grants = TestGrants.Create(provider);
        var (issued, _) = await grants.IssueAsync(user.Id, MfaOperations.AdminRotateSecret, "client-1",
            null, TotpCode(secret), null, CancellationToken.None);

        Assert.False(await grants.ConsumeAsync(other.Id, issued!.GrantId, MfaOperations.AdminRotateSecret, "client-1",
            null, CancellationToken.None));
    }

    [Fact]
    public async Task Consume_AfterSecurityStampRotation_Fails()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTotpUserAsync(provider);
        var grants = TestGrants.Create(provider);
        var (issued, _) = await grants.IssueAsync(user.Id, MfaOperations.AdminDeactivate, "user-9",
            new Dictionary<string, string?> { ["confirmUserName"] = "victim" }, TotpCode(secret), null, CancellationToken.None);

        // 签发后账号安全版本变化（角色/因子/密码变更都会轮换安全戳）：旧授权立即失效。
        user.SecurityStamp = "rotated-stamp";
        await provider.GetRequiredService<UserService>().UpdateAsync(user);

        Assert.False(await grants.ConsumeAsync(user.Id, issued!.GrantId, MfaOperations.AdminDeactivate, "user-9",
            new Dictionary<string, string?> { ["confirmUserName"] = "victim" }, CancellationToken.None));
    }

    [Fact]
    public async Task Consume_ExpiredGrant_Fails()
    {
        var time = new StubTimeProvider(DateTimeOffset.UtcNow);
        using var provider = TestUserStoreHost.Create(clock: time);
        var (user, secret) = await SeedTotpUserAsync(provider, time);
        var grants = TestGrants.Create(provider, time);
        var code = TotpCode(secret);
        var (issued, _) = await grants.IssueAsync(user.Id, MfaOperations.AdminResetTwoFactor, "user-9",
            null, code, null, CancellationToken.None);

        time.Advance(MfaOperationGrantService.GrantLifetime + TimeSpan.FromSeconds(1));

        Assert.False(await grants.ConsumeAsync(user.Id, issued!.GrantId, MfaOperations.AdminResetTwoFactor, "user-9",
            null, CancellationToken.None));
    }

    [Fact]
    public async Task AdminEndpoint_WithoutGrantHeader_ReturnsGrantRequiredMarker()
    {
        var (provider, _) = AdminTestHost.Create();
        using (provider)
        {
        var (controller, _) = AdminUsersController(provider);

        var denied = Assert.IsType<ObjectResult>(await controller.UpdateRoles(
            "user-9", new PandaAuth.Shared.AdminUserRolesRequest(["admin"]), CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, denied.StatusCode);
        dynamic marker = denied.Value!;
        Assert.True((bool)marker.mfaGrantRequired);
        Assert.Equal(MfaOperations.AdminUpdateRoles, (string)marker.operation);
        Assert.True((bool)marker.passwordRequired);
        }
    }

    // ---- 基建 ----

    private static async Task<(PandaUser User, byte[] Secret)> SeedTotpUserAsync(
        ServiceProvider provider, TimeProvider? clock = null)
    {
        var users = provider.GetRequiredService<UserService>();
        var roles = provider.GetRequiredService<RoleService>();
        if (!await roles.RoleExistsAsync(PandaUser.AdminRole))
            Assert.True((await roles.CreateAsync(new PandaRole { Name = PandaUser.AdminRole })).Succeeded);
        var user = new PandaUser { UserName = $"grant-admin-{Guid.NewGuid():N}", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        Assert.True((await users.AddToRoleAsync(user, PandaUser.AdminRole)).Succeeded);

        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        var factorId = Guid.NewGuid();
        var protectedSecret = new TotpSecretProtector(TestGrants.TotpKey, "v1").Protect(user.Id, factorId, secret);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor
        {
            Id = factorId,
            UserId = user.Id,
            ConfirmedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            KeyVersion = protectedSecret.KeyVersion,
            Nonce = protectedSecret.Nonce,
            Ciphertext = protectedSecret.Ciphertext,
            Tag = protectedSecret.Tag,
        });
        await db.SaveChangesAsync();
        return (user, secret);
    }

    private static (AdminUsersController Controller, DefaultHttpContext Context) AdminUsersController(ServiceProvider provider)
    {
        var context = AdminTestHost.HttpContext(provider);
        context.User = AdminTestHost.AdminPrincipalWithoutMfa();
        var controller = new AdminUsersController(
            provider.GetRequiredService<UserService>(),
            provider.GetRequiredService<RoleService>(),
            provider.GetRequiredService<SessionSecurityService>(),
            provider.GetRequiredService<AdminAuditWriter>(),
            provider.GetRequiredService<SecurityEventWriter>(),
            TestGrants.Create(provider),
            provider.GetRequiredService<PandaAuthDbContext>(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<AdminUsersController>.Instance)
        {
            ControllerContext = new() { HttpContext = context },
        };
        return (controller, context);
    }

    /// <summary>标准 RFC 6238（SHA1/30s/6 位）生成当前验证码——独立于生产 TotpVerifier 实现，互为印证。</summary>
    private static string TotpCode(byte[] secret)
    {
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> counter = stackalloc byte[8];
        for (var index = counter.Length - 1; index >= 0; index--)
        {
            counter[index] = (byte)step;
            step >>= 8;
        }
        using var hmac = new System.Security.Cryptography.HMACSHA1(secret);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) |
                     (hash[offset + 1] << 16) |
                     (hash[offset + 2] << 8) |
                     hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private sealed class StubTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delta) => _now += delta;
    }
}
