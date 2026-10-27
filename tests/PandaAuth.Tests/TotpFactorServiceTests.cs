using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class TotpFactorServiceTests
{
    [Fact]
    public async Task BeginEnrollment_NoPriorFactorRequired_AfterPasskeyRetirement()
    {
        // Passkey 退役（AUTH-DELIVERY-002）：TOTP 是唯一可验证因子，可直接作首因子绑定；
        // 旧的「先有 Passkey 才能启用 TOTP」约束已随 retire 一并移除。
        await using var db = Database();
        var service = Service(db);

        var enrollment = await service.BeginEnrollmentAsync("admin-1", CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(enrollment.Secret));
        Assert.Single(db.TotpFactors);
    }

    [Fact]
    public async Task BeginEnrollment_PersistsOnlyProtectedSecret()
    {
        await using var db = Database();
        var service = Service(db);

        var enrollment = await service.BeginEnrollmentAsync("admin-1", CancellationToken.None);
        var factor = Assert.Single(db.TotpFactors);

        Assert.Equal(factor.Id, enrollment.FactorId);
        Assert.NotEmpty(factor.Ciphertext);
        Assert.DoesNotContain(enrollment.Secret, Convert.ToBase64String(factor.Ciphertext), StringComparison.Ordinal);
        Assert.Null(factor.ConfirmedAt);
    }

    [Fact]
    public async Task BeginEnrollment_ReplacesAbandonedPendingFactor()
    {
        await using var db = Database();
        db.TotpFactors.Add(new MfaTotpFactor { UserId = "member-1", Id = Guid.NewGuid() });
        await db.SaveChangesAsync();
        var service = Service(db);

        var enrollment = await service.BeginEnrollmentAsync("member-1", CancellationToken.None);

        var factors = await db.TotpFactors.Where(x => x.UserId == "member-1").ToListAsync();
        Assert.Equal(2, factors.Count);
        Assert.Contains(factors, factor => factor.Id == enrollment.FactorId && factor.RevokedAt is null);
        Assert.Contains(factors, factor => factor.RevokedAt is not null);
    }

    private static PandaAuthDbContext Database() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);

    private static TotpFactorService Service(PandaAuthDbContext db) => new(db,
        new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System);
}
