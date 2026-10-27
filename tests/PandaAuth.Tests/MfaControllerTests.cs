using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// MFA 自助面（Passkey 退役后，AUTH-DELIVERY-002）：管理员页 TOTP-first、
/// 特敏感自助操作（恢复码重生成/TOTP 换绑/撤销 TOTP）须持单次操作授权，
/// 退役 passkey 行撤销走迁移动作口径。
/// </summary>
public class MfaControllerTests
{
    [Fact]
    public async Task OrdinaryUser_StatusCountsRetiredPasskeysAndRecoveryCodes_GenerateViaRecentTotp()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member-mfa", Email = "member-mfa@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        await SeedConfirmedTotpAsync(db, user.Id, secret);
        await db.SaveChangesAsync();
        var (context, principal) = await TestGrants.SignedInContextAsync(provider, user, MfaClaimTypes.Totp);
        var controller = CreateUserMfaController(provider, context, principal);

        var status = Assert.IsType<JsonResult>(await controller.UserStatus(CancellationToken.None));
        var value = Assert.IsType<MfaStatus>(status.Value);
        Assert.True(value.HasActiveFactor);

        // 已绑定 TOTP → 恢复码重生成须持单次操作授权（TOTP + 本人密码）。
        var grants = TestGrants.Create(provider);
        var (issued, issueError) = await grants.IssueAsync(user.Id, MfaOperations.SelfRecoveryCodes, user.Id,
            null, TotpCode(secret), "Strong!Pass123", CancellationToken.None);
        Assert.True(issued is not null, $"grant failed: {issueError}");
        context.Request.Headers[MfaOperationGrantGate.GrantHeader] = issued!.GrantId.ToString();

        var generated = Assert.IsType<JsonResult>(await controller.GenerateUserRecoveryCodes(CancellationToken.None));
        Assert.Equal(10, ((IReadOnlyList<string>)generated.Value!).Count);
    }

    [Fact]
    public async Task RecoveryCodes_WithVerifiableFactorButNoGrant_ReturnsGrantRequired()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, _) = await SeedConfirmedTotpUserAsync(provider, "grantless-member");
        var (context, principal) = await TestGrants.SignedInContextAsync(provider, user, MfaClaimTypes.Totp);
        var controller = CreateUserMfaController(provider, context, principal);

        var denied = Assert.IsType<ObjectResult>(await controller.GenerateUserRecoveryCodes(CancellationToken.None));

        Assert.Equal(StatusCodes.Status403Forbidden, denied.StatusCode);
        Assert.Equal("true", context.Response.Headers[MfaOperationGrantGate.GrantRequiredHeader].ToString());
        dynamic marker = denied.Value!;
        Assert.True((bool)marker.mfaGrantRequired);
        Assert.Equal(MfaOperations.SelfRecoveryCodes, (string)marker.operation);
        Assert.True((bool)marker.passwordRequired);
    }

    [Fact]
    public async Task TotpEnroll_Rebind_RequiresGrant_FirstBindUsesFirstFactorUnlock()
    {
        using var provider = TestUserStoreHost.Create();
        // 首绑：无可验证因子，5 分钟内密码登录即可。
        var freshUser = new PandaUser { UserName = "first-bind", Email = "first@example.com", EmailConfirmed = true };
        Assert.True((await provider.GetRequiredService<UserService>().CreateAsync(freshUser, "Strong!Pass123")).Succeeded);
        var (freshContext, freshPrincipal) = await TestGrants.SignedInContextAsync(provider, freshUser);
        var freshController = CreateUserMfaController(provider, freshContext, freshPrincipal);
        Assert.IsType<OkObjectResult>(await freshController.BeginUserTotp(CancellationToken.None));

        // 换绑：已有 TOTP，未带授权头 → 403 授权标记。
        var (boundUser, _) = await SeedConfirmedTotpUserAsync(provider, "rebind-member");
        var (context, principal) = await TestGrants.SignedInContextAsync(provider, boundUser);
        var controller = CreateUserMfaController(provider, context, principal);
        var denied = Assert.IsType<ObjectResult>(await controller.BeginUserTotp(CancellationToken.None));
        Assert.Equal(StatusCodes.Status403Forbidden, denied.StatusCode);
        Assert.Equal("true", context.Response.Headers[MfaOperationGrantGate.GrantRequiredHeader].ToString());
    }

    [Fact]
    public async Task RevokeLastTotp_WithValidGrant_ConsumedButStillGuardedByServer()
    {
        // 轮换机制下唯一 TOTP 是稳态（确认新因子即撤旧），撤销它注定被服务层护栏拒绝；
        // 此用例钉住「授权签发/消费成功 ≠ 业务放行」——消费与受保护动作保持一致。
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedConfirmedTotpUserAsync(provider, "guard-member");
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var totpId = await db.TotpFactors.AsNoTracking()
            .Where(x => x.UserId == user.Id && x.RevokedAt == null && x.ConfirmedAt != null)
            .Select(x => x.Id).SingleAsync();
        var grants = TestGrants.Create(provider);
        var issued = await grants.IssueAsync(user.Id, MfaOperations.SelfRevokeFactor, totpId.ToString(),
            new Dictionary<string, string?> { ["factorType"] = "totp" },
            TotpCode(secret), "Strong!Pass123", CancellationToken.None);
        Assert.NotNull(issued.Issued);
        var (context, principal) = await TestGrants.SignedInContextAsync(provider, user, MfaClaimTypes.Totp);
        context.Request.Headers[MfaOperationGrantGate.GrantHeader] = issued.Issued!.GrantId.ToString();
        var controller = CreateUserMfaController(provider, context, principal);
        var rejected = Assert.IsType<BadRequestObjectResult>(await controller.RevokeUserFactor(
            new RevokeMfaFactorRequest { FactorId = totpId }, CancellationToken.None));
        Assert.Contains("Cannot remove the last active factor", rejected.Value!.ToString(), StringComparison.Ordinal);
        Assert.NotNull((await db.TotpFactors.AsNoTracking().SingleAsync(x => x.Id == totpId)).ConfirmedAt);
    }

    [Fact]
    public async Task Enrollment_UnconfirmedAdministrator_IsForbiddenBeforeCreatingSecrets()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var roles = provider.GetRequiredService<RoleService>();
        Assert.True((await roles.CreateAsync(new PandaRole { Name = PandaUser.AdminRole })).Succeeded);
        var user = new PandaUser { UserName = "unconfirmed-admin", Email = "admin@example.com" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        Assert.True((await users.AddToRoleAsync(user, PandaUser.AdminRole)).Succeeded);
        var context = new DefaultHttpContext { RequestServices = provider };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, user.Id)], LoginSessionService.Scheme));
        var controller = CreateUserMfaController(provider, context, context.User);

        Assert.IsType<ForbidResult>(await controller.BeginTotp(CancellationToken.None));
    }

    [Fact]
    public async Task Index_NonAdministrator_IsForbidden()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member" };
        await users.CreateAsync(user, "Strong!Pass123");
        var context = new DefaultHttpContext { RequestServices = provider };
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.Id)], LoginSessionService.Scheme));
        var controller = CreateUserMfaController(provider, context, context.User);

        Assert.IsType<ForbidResult>(await controller.Index(null, CancellationToken.None));
    }

    [Fact]
    public async Task UserFactors_ListsConfirmedTotpAndActivePasskeys_Only()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "factors-member", Email = "factors@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        await SeedConfirmedTotpAsync(db, user.Id);
        await db.SaveChangesAsync();
        var controller = CreateUserMfaController(provider, user.Id);

        var result = Assert.IsType<JsonResult>(await controller.UserFactors(CancellationToken.None));

        var factors = Assert.IsAssignableFrom<IReadOnlyList<MfaFactorInfo>>(result.Value);
        var factor = Assert.Single(factors);
        Assert.Equal("totp", factor.Type);
    }

    [Fact]
    public void UserAntiforgeryToken_IssuesRequestTokenForAuthenticatedUser()
    {
        using var provider = TestUserStoreHost.Create();
        var user = new PandaUser { UserName = "csrf-member" };
        provider.GetRequiredService<UserService>().CreateAsync(user, "Strong!Pass123");
        var controller = CreateUserMfaController(provider, user.Id);

        var result = Assert.IsType<OkObjectResult>(
            controller.UserAntiforgeryToken(provider.GetRequiredService<IAntiforgery>()));

        var token = (string?)result.Value?.GetType().GetProperty("token")?.GetValue(result.Value);
        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task AdminFirstTotpBind_WithFreshPasswordLogin_CanStartEnrollment()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        var controller = CreateAdminMfaController(provider, user.Id, authenticatedAt: DateTimeOffset.UtcNow);

        var enrollment = Assert.IsType<OkObjectResult>(await controller.BeginTotp(CancellationToken.None));
        Assert.NotNull(enrollment.Value);
    }

    [Fact]
    public async Task AdminTotpRebind_OnAdminPage_IsRejected_DirectedToAccountCenter()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        await SeedConfirmedTotpAsync(provider.GetRequiredService<PandaAuthDbContext>(), user.Id);
        var controller = CreateAdminMfaController(provider, user.Id, recentMfaMethod: MfaClaimTypes.Totp);

        var rejected = Assert.IsType<BadRequestObjectResult>(await controller.BeginTotp(CancellationToken.None));
        Assert.Contains("账户中心", rejected.Value!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AdminEnrollment_WithoutRecentAuthentication_IsForbidden()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        var controller = CreateAdminMfaController(provider, user.Id, authenticatedAt: null);

        Assert.IsType<ForbidResult>(await controller.BeginTotp(CancellationToken.None));
    }

    [Fact]
    public async Task AdminAssertTotp_IsRateLimitedPerUser()
    {
        var options = new PandaAuth.Server.Configuration.AuthOptions();
        options.RateLimit.MfaChallengeAccountPerMinute = 2;
        using var provider = TestUserStoreHost.Create(options);
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        await SeedConfirmedTotpAsync(provider.GetRequiredService<PandaAuthDbContext>(), user.Id);
        var controller = CreateAdminMfaController(provider, user.Id, authenticatedAt: DateTimeOffset.UtcNow);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var bad = Assert.IsType<BadRequestObjectResult>(await controller.AssertTotp(
                new ConfirmTotpRequest { Code = "000000" }, CancellationToken.None));
            Assert.Contains("验证码错误", bad.Value!.ToString(), StringComparison.Ordinal);
        }

        var limited = Assert.IsType<ObjectResult>(await controller.AssertTotp(
            new ConfirmTotpRequest { Code = "000000" }, CancellationToken.None));
        Assert.Equal(StatusCodes.Status429TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task AdminConfirmTotp_RejectsAlreadyConfirmedFactor()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        var factorId = await SeedConfirmedTotpAsync(provider.GetRequiredService<PandaAuthDbContext>(), user.Id);
        var controller = CreateAdminMfaController(
            provider, user.Id, recentMfaMethod: MfaClaimTypes.Totp);

        var result = Assert.IsType<BadRequestObjectResult>(await controller.ConfirmTotp(
            new ConfirmTotpRequest { FactorId = factorId, Code = "000000" }, CancellationToken.None));

        Assert.Contains("验证码错误", result.Value!.ToString(), StringComparison.Ordinal);
    }

    // ---- 基建 ----

    private static async Task<(PandaUser User, byte[] Secret)> SeedConfirmedTotpUserAsync(
        ServiceProvider provider, string userName)
    {
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = userName, Email = $"{userName}@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        await SeedConfirmedTotpAsync(provider.GetRequiredService<PandaAuthDbContext>(), user.Id, secret: secret);
        return (user, secret);
    }

    private static async Task<Guid> SeedConfirmedTotpAsync(
        PandaAuth.Server.Infrastructure.Persistence.PandaAuthDbContext db, string userId, byte[]? secret = null)
    {
        var factorId = Guid.NewGuid();
        var plainSecret = secret ?? System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        var protector = new TotpSecretProtector(TestGrants.TotpKey, "v1");
        var protectedSecret = protector.Protect(userId, factorId, plainSecret);
        db.TotpFactors.Add(new MfaTotpFactor
        {
            Id = factorId,
            UserId = userId,
            ConfirmedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            KeyVersion = protectedSecret.KeyVersion,
            Nonce = protectedSecret.Nonce,
            Ciphertext = protectedSecret.Ciphertext,
            Tag = protectedSecret.Tag,
        });
        await db.SaveChangesAsync();
        return factorId;
    }

    private static async Task<PandaUser> SeedAdminAsync(ServiceProvider provider, bool emailConfirmed)
    {
        var users = provider.GetRequiredService<UserService>();
        var roles = provider.GetRequiredService<RoleService>();
        if (!await roles.RoleExistsAsync(PandaUser.AdminRole))
            Assert.True((await roles.CreateAsync(new PandaRole { Name = PandaUser.AdminRole })).Succeeded);
        var user = new PandaUser
        {
            UserName = $"admin-{Guid.NewGuid():N}",
            Email = $"{Guid.NewGuid():N}@example.com",
            EmailConfirmed = emailConfirmed,
        };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        Assert.True((await users.AddToRoleAsync(user, PandaUser.AdminRole)).Succeeded);
        return user;
    }

    private static MfaController CreateUserMfaController(
        ServiceProvider provider, HttpContext context, ClaimsPrincipal principal)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var totp = new TotpFactorService(db, new TotpSecretProtector(TestGrants.TotpKey, "v1"), TimeProvider.System);
        return new MfaController(
            provider.GetRequiredService<UserService>(),
            totp,
            provider.GetRequiredService<LoginSessionService>(),
            db,
            TestGrants.Create(provider),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            new MfaService(db, provider.GetRequiredService<UserService>(), totp,
                provider.GetRequiredService<LoginSessionService>(), TimeProvider.System),
            provider.GetRequiredService<SecurityEventWriter>())
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
    }

    private static MfaController CreateUserMfaController(ServiceProvider provider, string userId)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId)], LoginSessionService.Scheme));
        return CreateUserMfaController(provider, context, context.User);
    }

    private static MfaController CreateAdminMfaController(
        ServiceProvider provider, string userId, DateTimeOffset? authenticatedAt = null, string? recentMfaMethod = null)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.10");
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, userId) };
        if (authenticatedAt is not null)
            claims.Add(new Claim(LoginSessionService.AuthenticatedAtClaim,
                authenticatedAt.Value.ToUnixTimeSeconds().ToString()));
        if (recentMfaMethod is not null)
        {
            claims.Add(new Claim(MfaClaimTypes.Method, recentMfaMethod));
            claims.Add(new Claim(MfaClaimTypes.VerifiedAt,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        }
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, LoginSessionService.Scheme));
        var totp = new TotpFactorService(db, new TotpSecretProtector(TestGrants.TotpKey, "v1"), TimeProvider.System);
        return new MfaController(
            provider.GetRequiredService<UserService>(),
            totp,
            provider.GetRequiredService<LoginSessionService>(),
            db,
            TestGrants.Create(provider),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            new MfaService(db, provider.GetRequiredService<UserService>(), totp,
                provider.GetRequiredService<LoginSessionService>(), TimeProvider.System),
            provider.GetRequiredService<SecurityEventWriter>())
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
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
}
