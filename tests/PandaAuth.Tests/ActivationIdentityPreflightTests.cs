using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PandaAuth.ReadinessHarness;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

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
        var duplicate = new PandaUser { Id = "other-id", UserName = "other", NormalizedUserName = user.NormalizedUserName };
        db.Users.Add(duplicate); await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckAsync(db, name, Hash(name), expected, true, DateTimeOffset.UtcNow));
        db.Users.Remove(duplicate); await db.SaveChangesAsync();
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

    [Fact]
    public async Task ClientPreflightRequiresTheActualConfidentialClientCallbackAndProtocolPermissions()
    {
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).UseOpenIddict().Options);
        var callback = "https://auth.appliket.com/admin/callback/login/pandaauth";
        string[] permissions = [Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Revocation, Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code, Permissions.Scopes.Email, Permissions.Scopes.Profile, Permissions.Scopes.Roles,
            Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope];
        var app = new OpenIddictEntityFrameworkCoreApplication { Id = "fixture", ClientId = "admin-web", ClientType = "confidential",
            ClientSecret = "synthetic-only", RedirectUris = JsonSerializer.Serialize(new[] { callback }), Permissions = JsonSerializer.Serialize(permissions) };
        db.Set<OpenIddictEntityFrameworkCoreApplication>().Add(app); await db.SaveChangesAsync();
        Assert.True(await ActivationIdentityPreflight.CheckClientAsync(db, "admin", "https://auth.appliket.com/", callback));
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckClientAsync(db, "admin", "https://auth.appliket.com/", "https://foreign.invalid/callback"));
        app.Permissions = JsonSerializer.Serialize(permissions.Where(value => value != Permissions.Endpoints.Revocation)); await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckClientAsync(db, "admin", "https://auth.appliket.com/", callback));
        app.Permissions = JsonSerializer.Serialize(permissions); app.ClientType = "public"; await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckClientAsync(db, "admin", "https://auth.appliket.com/", callback));
        var meCallback = "https://auth.appliket.com/me/callback/login/pandaauth";
        app.ClientId = "me-web"; app.ClientType = "confidential"; app.RedirectUris = JsonSerializer.Serialize(new[] { meCallback });
        app.Permissions = JsonSerializer.Serialize(permissions.Where(value => value != Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope));
        await db.SaveChangesAsync();
        Assert.True(await ActivationIdentityPreflight.CheckClientAsync(db, "me", "https://auth.appliket.com/", meCallback));
        app.Permissions = JsonSerializer.Serialize(permissions); await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckClientAsync(db, "me", "https://auth.appliket.com/", meCallback));
        app.Permissions = "[invalid"; await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckClientAsync(db, "me", "https://auth.appliket.com/", meCallback));
    }

    [Fact]
    public async Task ClientSecretUsesTheActualOpenIddictVerifierBeforeAnyHumanLogin()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PandaAuthDbContext>(options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()).UseOpenIddict());
        services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(new OpenIddictApplicationDescriptor { ClientId = "admin-web", ClientType = ClientTypes.Confidential, ClientSecret = "fixture-only" });
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.True(await ActivationIdentityPreflight.CheckClientSecretAsync(db, "admin-web", "fixture-only"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckClientSecretAsync(db, "admin-web", "wrong-fixture"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationIdentityPreflight.CheckClientSecretAsync(db, "unapproved-client", "fixture-only"));
        Assert.False(db.ChangeTracker.HasChanges());
    }
}
