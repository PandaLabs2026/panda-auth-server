using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class TotpFactorServiceTests
{
    [Fact]
    public async Task BeginEnrollment_RequiresExistingActivePasskey()
    {
        await using var db = Database();
        var service = Service(db);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.BeginEnrollmentAsync("admin-1", CancellationToken.None));
    }

    [Fact]
    public async Task BeginEnrollment_PersistsOnlyProtectedSecret()
    {
        await using var db = Database();
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential { UserId = "admin-1", CredentialId = [1], PublicKeyCose = [2] });
        await db.SaveChangesAsync();
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

        var enrollment = await service.BeginEnrollmentAsync("member-1", CancellationToken.None, requirePasskey: false);

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
