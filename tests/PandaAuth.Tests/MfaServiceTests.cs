using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public sealed class MfaServiceTests
{
    [Fact]
    public async Task BeginEnrollment_RequiresConfirmedEmailAndRecentAuthentication()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member", Email = "member@example.com", EmailConfirmed = false };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = CreateService(provider);

        await Assert.ThrowsAsync<MfaPolicyException>(() => service.BeginEnrollmentAsync(
            user.Id, Principal(user.Id), CancellationToken.None));

        user.EmailConfirmed = true;
        await users.UpdateAsync(user);

        await Assert.ThrowsAsync<MfaPolicyException>(() => service.BeginEnrollmentAsync(
            user.Id, Principal(user.Id), CancellationToken.None));
    }

    [Fact]
    public async Task RecoveryCodes_AreReturnedOnceHashedAndSingleUse()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member", Email = "member@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = CreateService(provider);
        var principal = Principal(user.Id, recentMethod: MfaClaimTypes.Totp);

        var codes = await service.GenerateRecoveryCodesAsync(user.Id, principal, CancellationToken.None);

        Assert.NotEmpty(codes);
        var stored = await provider.GetRequiredService<PandaAuthDbContext>().MfaRecoveryCodes.ToListAsync();
        Assert.Equal(codes.Count, stored.Count);
        Assert.All(stored, code =>
        {
            Assert.NotEqual(codes[0], code.CodeHash);
            Assert.NotEqual(string.Empty, code.Salt);
            Assert.Null(code.ConsumedAt);
        });

        Assert.True(await service.ConsumeRecoveryCodeAsync(user.Id, codes[0], CancellationToken.None));
        Assert.False(await service.ConsumeRecoveryCodeAsync(user.Id, codes[0], CancellationToken.None));
        Assert.False(await service.ConsumeRecoveryCodeAsync(user.Id, "not-a-recovery-code", CancellationToken.None));
        Assert.NotNull((await provider.GetRequiredService<PandaAuthDbContext>().MfaRecoveryCodes.SingleAsync(
            code => code.CodeHash == stored[0].CodeHash)).ConsumedAt);
    }

    [Fact]
    public async Task OrdinaryUser_CanBeginTotpEnrollmentWithoutExistingPasskey()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "totp-member", Email = "totp@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = CreateService(provider);

        var enrollment = await service.BeginEnrollmentAsync(
            user.Id, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);

        Assert.NotEqual(Guid.Empty, enrollment.FactorId);
        Assert.StartsWith("otpauth://totp/", enrollment.ProvisioningUri);
    }

    [Fact]
    public async Task ConfirmEnrollment_StillRequiresConfirmedEmailAndRecentMfa()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "confirm-gated", Email = "confirm-gated@example.com", EmailConfirmed = false };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = CreateService(provider);

        await Assert.ThrowsAsync<MfaPolicyException>(() => service.ConfirmEnrollmentAsync(
            user.Id, Principal(user.Id), Guid.NewGuid(), "000000", CancellationToken.None));
    }

    [Fact]
    public async Task RevokeFactor_DoesNotAllowRemovingTheLastActiveFactor()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member", Email = "member@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        var factorId = db.TotpFactors.Single().Id;
        var service = CreateService(provider);

        await Assert.ThrowsAsync<MfaPolicyException>(() => service.RevokeFactorAsync(
            user.Id, factorId, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None));
    }

    [Fact]
    public async Task RevokeFactor_AllowsRemovingOneOfTwoActiveFactors()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "two-factors", Email = "two-factors@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        // 两个已确认 TOTP：可验证因子口径下撤销其一不触发「最后一个因子」护栏。
        var first = new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow };
        var second = new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow };
        db.TotpFactors.Add(first);
        db.TotpFactors.Add(second);
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        await service.RevokeFactorAsync(user.Id, first.Id, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);

        Assert.NotNull((await db.TotpFactors.SingleAsync(x => x.Id == first.Id)).RevokedAt);
        Assert.Null((await db.TotpFactors.SingleAsync(x => x.Id == second.Id)).RevokedAt);
    }

    [Fact]
    public async Task TotpRotation_NewConfirmRevokesSupersededFactorWithoutGap()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "rotating", Email = "rotating@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = CreateService(provider);
        var principal = Principal(user.Id, recentMethod: MfaClaimTypes.Totp);

        var first = await service.BeginEnrollmentAsync(user.Id, principal, CancellationToken.None);
        Assert.True(await service.ConfirmEnrollmentAsync(
            user.Id, principal, first.FactorId, TestGrants.TotpCode(FromBase32(first.Secret)), CancellationToken.None));

        // 轮换：已有确认因子时仍可再开 pending（旧因子保持可用，无无因子窗口）。
        var second = await service.BeginEnrollmentAsync(user.Id, principal, CancellationToken.None);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(2, await db.TotpFactors.CountAsync(x => x.UserId == user.Id && x.RevokedAt == null));

        // 确认新因子 = 换绑收口：旧确认因子被原子撤销，只剩新因子。
        Assert.True(await service.ConfirmEnrollmentAsync(
            user.Id, principal, second.FactorId, TestGrants.TotpCode(FromBase32(second.Secret)), CancellationToken.None));
        var active = await db.TotpFactors
            .Where(x => x.UserId == user.Id && x.RevokedAt == null && x.ConfirmedAt != null)
            .ToListAsync();
        Assert.Equal(second.FactorId, Assert.Single(active).Id);
    }

    private static byte[] FromBase32(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = 0;
        var buffer = 0;
        var output = new List<byte>();
        foreach (var character in value)
        {
            buffer = (buffer << 5) | alphabet.IndexOf(character);
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((buffer >> (bits - 8)) & 0xff));
                bits -= 8;
            }
        }
        return [.. output];
    }

    [Fact]
    public async Task LegacyTwoFactorWithoutActiveFactor_RequiresReconfiguration()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "legacy", Email = "legacy@example.com", TwoFactorEnabled = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var status = await CreateService(provider).GetStatusAsync(user.Id, CancellationToken.None);

        Assert.True(status.RequiresReconfiguration);
    }

    [Fact]
    public async Task FirstFactor_CanEnrollWithFreshPasswordLogin()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "first-factor", Email = "first-factor@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = CreateService(provider);

        var enrollment = await service.BeginEnrollmentAsync(
            user.Id, Principal(user.Id, authenticatedAt: DateTimeOffset.UtcNow), CancellationToken.None);

        Assert.NotEqual(Guid.Empty, enrollment.FactorId);
    }

    [Fact]
    public async Task FirstFactor_AfterAdminReset_IsBlockedForSessionIssuedBeforeReset()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "reset-before-login", Email = "reset-before-login@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.MfaRecoveryEvents.Add(new MfaRecoveryEvent
        {
            ActorUserId = "admin",
            TargetUserId = user.Id,
            Reason = MfaRecoveryEvent.AdminResetReason,
            AuthenticationMethod = MfaClaimTypes.Totp,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        // 重置前签发的密码会话：即使仍在 5 分钟内，也不能用首因子解锁重新绑定。
        await Assert.ThrowsAsync<MfaPolicyException>(() => service.BeginEnrollmentAsync(
            user.Id,
            Principal(user.Id, authenticatedAt: DateTimeOffset.UtcNow.AddMinutes(-1)),
            CancellationToken.None));
    }

    [Fact]
    public async Task FirstFactor_AfterAdminReset_AllowsFreshLoginIssuedAfterReset()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "reset-after-login", Email = "reset-after-login@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.MfaRecoveryEvents.Add(new MfaRecoveryEvent
        {
            ActorUserId = "admin",
            TargetUserId = user.Id,
            Reason = MfaRecoveryEvent.AdminResetReason,
            AuthenticationMethod = MfaClaimTypes.Totp,
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-1),
        });
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        var enrollment = await service.BeginEnrollmentAsync(
            user.Id, Principal(user.Id, authenticatedAt: DateTimeOffset.UtcNow), CancellationToken.None);

        Assert.NotEqual(Guid.Empty, enrollment.FactorId);
    }

    [Fact]
    public async Task RevokeFactor_ClearsRecoveryCodes()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "revoke-codes", Email = "revoke-codes@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        // 两个已确认 TOTP：撤销其一不触发「最后一个因子」护栏。
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        db.MfaRecoveryCodes.Add(new MfaRecoveryCode { UserId = user.Id, CodeHash = "00", Salt = "00" });
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        // 撤销 TOTP（可验证因子）作废恢复码。
        var totpId = await db.TotpFactors.Where(x => x.UserId == user.Id && x.ConfirmedAt != null).Select(x => x.Id).FirstAsync();
        await service.RevokeFactorAsync(user.Id, totpId, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);
        Assert.Empty(await db.MfaRecoveryCodes.Where(code => code.UserId == user.Id).ToListAsync());
    }

    [Fact]
    public async Task FirstFactor_RequiresRecentLogin_NotStaleSession()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "stale-login", Email = "stale@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var service = CreateService(provider);

        await Assert.ThrowsAsync<MfaPolicyException>(() => service.BeginEnrollmentAsync(
            user.Id,
            Principal(user.Id, authenticatedAt: DateTimeOffset.UtcNow.AddMinutes(-10)),
            CancellationToken.None));
    }

    [Fact]
    public async Task SecondFactor_StillRequiresRecentMfa_NotJustFreshLogin()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "second-factor", Email = "second@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        await Assert.ThrowsAsync<MfaPolicyException>(() => service.BeginEnrollmentAsync(
            user.Id, Principal(user.Id, authenticatedAt: DateTimeOffset.UtcNow), CancellationToken.None));
    }

    private static MfaService CreateService(ServiceProvider provider)
        => new(
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<UserService>(),
            new TotpFactorService(provider.GetRequiredService<PandaAuthDbContext>(),
                new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"),
                TimeProvider.System),
            provider.GetRequiredService<LoginSessionService>(),
            TimeProvider.System);

    private static ClaimsPrincipal Principal(string userId, string? recentMethod = null, DateTimeOffset? authenticatedAt = null)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, userId) };
        if (recentMethod is not null)
        {
            claims.Add(new Claim(MfaClaimTypes.Method, recentMethod));
            claims.Add(new Claim(MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        }

        if (authenticatedAt is not null)
        {
            claims.Add(new Claim(LoginSessionService.AuthenticatedAtClaim,
                authenticatedAt.Value.ToUnixTimeSeconds().ToString()));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, LoginSessionService.Scheme));
    }
}
