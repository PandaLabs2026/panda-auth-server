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
            user.Id, Principal(user.Id), MfaFactorType.Totp, CancellationToken.None));

        user.EmailConfirmed = true;
        await users.UpdateAsync(user);

        await Assert.ThrowsAsync<MfaPolicyException>(() => service.BeginEnrollmentAsync(
            user.Id, Principal(user.Id), MfaFactorType.Totp, CancellationToken.None));
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
            user.Id, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), MfaFactorType.Totp, CancellationToken.None);

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
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        var passkey = new MfaWebAuthnCredential { UserId = user.Id, Id = Guid.NewGuid(), CredentialId = [1], PublicKeyCose = [2] };
        db.WebAuthnCredentials.Add(passkey);
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        await service.RevokeFactorAsync(user.Id, passkey.Id, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);

        Assert.NotNull((await db.WebAuthnCredentials.SingleAsync(x => x.Id == passkey.Id)).RevokedAt);
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
            user.Id, Principal(user.Id, authenticatedAt: DateTimeOffset.UtcNow), MfaFactorType.Totp, CancellationToken.None);

        Assert.NotEqual(Guid.Empty, enrollment.FactorId);
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
            MfaFactorType.Totp,
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
            user.Id, Principal(user.Id, authenticatedAt: DateTimeOffset.UtcNow), MfaFactorType.Totp, CancellationToken.None));
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
