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
    public async Task LegacyTwoFactorWithoutActiveFactor_RequiresReconfiguration()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "legacy", Email = "legacy@example.com", TwoFactorEnabled = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var status = await CreateService(provider).GetStatusAsync(user.Id, CancellationToken.None);

        Assert.True(status.RequiresReconfiguration);
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

    private static ClaimsPrincipal Principal(string userId, string? recentMethod = null)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, userId) };
        if (recentMethod is not null)
        {
            claims.Add(new Claim(MfaClaimTypes.Method, recentMethod));
            claims.Add(new Claim(MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, LoginSessionService.Scheme));
    }
}
