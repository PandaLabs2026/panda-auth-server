using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PandaAuth.ReadinessHarness;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ActivationIdentityPreflightTests
{
    [Fact]
    public async Task LookupMatchesApplicationNormalizationAndRejectsUnapprovedOrUnsafeAccounts()
    {
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var name = "café-user";
        var user = new PandaUser { Id = "approved-id", UserName = name, NormalizedUserName = name.Normalize().ToUpperInvariant(),
            Status = UserStatus.Active, EmailConfirmed = true, TwoFactorEnabled = true, PasswordHash = "synthetic-only" };
        var role = new PandaRole { Id = "role", Name = "admin", NormalizedName = "ADMIN" };
        var factor = new MfaTotpFactor { UserId = user.Id, ConfirmedAt = DateTimeOffset.UtcNow };
        db.Users.Add(user); db.Roles.Add(role); db.UserRoles.Add(new PandaUserRole { UserId = user.Id, RoleId = role.Id });
        db.TotpFactors.Add(factor); await db.SaveChangesAsync();
        var expected = Hash(user.Id);
        var service = new UserService(db, new Argon2idPasswordHasher(), TimeProvider.System);
        Assert.Equal(user.Id, (await service.FindByNameAsync(name))!.Id);
        Assert.True(await ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, true, DateTimeOffset.UtcNow));
        Assert.False(db.ChangeTracker.HasChanges());
        var alias = "cafe\u0301-user";
        Assert.Equal(user.Id, (await service.FindByNameAsync(alias))!.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, alias, Hash(alias), expected, true, DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), Hash("other"), true, DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, false, DateTimeOffset.UtcNow));
        role.Name = "different"; await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, true, DateTimeOffset.UtcNow));
        Assert.True(await ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, false, DateTimeOffset.UtcNow));
        role.Name = "admin"; await db.SaveChangesAsync();
        user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(5); await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, true, DateTimeOffset.UtcNow));
        user.LockoutEnd = null; user.Status = UserStatus.Frozen; await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, true, DateTimeOffset.UtcNow));
        user.Status = UserStatus.Active;
        factor.RevokedAt = DateTimeOffset.UtcNow; await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, true, DateTimeOffset.UtcNow));
    }
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
