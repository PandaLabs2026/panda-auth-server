using System.Security.Claims;
using Fido2NetLib;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class MfaControllerTests
{
    [Fact]
    public async Task OrdinaryUser_CanReadStatusAndGenerateRecoveryCodes()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member-mfa", Email = "member-mfa@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        db.TotpFactors.Add(new MfaTotpFactor
        {
            UserId = user.Id,
            Id = Guid.NewGuid(),
            ConfirmedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id,
            CredentialId = [1, 2, 3],
            PublicKeyCose = [4, 5, 6],
        });
        await db.SaveChangesAsync();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(MfaClaimTypes.Method, MfaClaimTypes.Totp),
                new Claim(MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            ], LoginSessionService.Scheme));
        var controller = new MfaController(
            users,
            new WebAuthnCeremonyService(new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                db, new MfaChallengeStore(provider.GetRequiredService<PandaAuthDbContext>(), TimeProvider.System)),
            new TotpFactorService(db,
                new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System),
            provider.GetRequiredService<LoginSessionService>(),
            db,
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            new MfaService(
                db,
                users,
                new TotpFactorService(db,
                    new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System),
                provider.GetRequiredService<LoginSessionService>(),
                TimeProvider.System))
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };

        var status = Assert.IsType<JsonResult>(await controller.UserStatus(CancellationToken.None));
        Assert.Equal(1, Assert.IsType<MfaStatus>(status.Value).ActivePasskeyCount);
        var generated = Assert.IsType<JsonResult>(await controller.GenerateUserRecoveryCodes(CancellationToken.None));
        Assert.Equal(10, ((IReadOnlyList<string>)generated.Value!).Count);
    }

    [Fact]
    public async Task Enrollment_UnconfirmedAdministrator_IsForbiddenBeforeCreatingSecretsOrCeremonies()
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
        var controller = new MfaController(
            users,
            new WebAuthnCeremonyService(new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                provider.GetRequiredService<PandaAuthDbContext>(),
                new MfaChallengeStore(provider.GetRequiredService<PandaAuthDbContext>(), TimeProvider.System)),
            new TotpFactorService(provider.GetRequiredService<PandaAuthDbContext>(),
                new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>())
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };

        Assert.IsType<ForbidResult>(await controller.EnrollmentOptions(CancellationToken.None));
        Assert.IsType<ForbidResult>(await controller.BeginTotp(CancellationToken.None));
    }

    [Fact]
    public async Task Index_NonAdministrator_IsForbiddenBeforeAnyPasskeyCeremony()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member" };
        await users.CreateAsync(user, "Strong!Pass123");
        var context = new DefaultHttpContext { RequestServices = provider };
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.Id)], LoginSessionService.Scheme));
        var controller = new MfaController(
            users,
            new WebAuthnCeremonyService(new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                provider.GetRequiredService<PandaAuthDbContext>(), new MfaChallengeStore(provider.GetRequiredService<PandaAuthDbContext>(), TimeProvider.System)),
            new TotpFactorService(provider.GetRequiredService<PandaAuthDbContext>(),
                new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>())
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };

        var result = await controller.Index(null, CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task UserFactors_ListsConfirmedTotpAndActivePasskeys_Only()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "factors-member", Email = "factors@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var passkeyId = Guid.NewGuid();
        db.TotpFactors.Add(new MfaTotpFactor
        {
            UserId = user.Id,
            Id = Guid.NewGuid(),
            ConfirmedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id,
            Id = passkeyId,
            CredentialId = [7],
            PublicKeyCose = [8],
            FriendlyName = "Windows Hello",
        });
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id,
            Id = Guid.NewGuid(),
            CredentialId = [9],
            PublicKeyCose = [10],
            RevokedAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();
        var controller = CreateUserMfaController(provider, user.Id);

        var result = Assert.IsType<JsonResult>(await controller.UserFactors(CancellationToken.None));

        var factors = Assert.IsAssignableFrom<IReadOnlyList<MfaFactorInfo>>(result.Value);
        Assert.Equal(2, factors.Count);
        Assert.Contains(factors, factor => factor.Type == "totp");
        var passkey = Assert.Single(factors, factor => factor.Type == "passkey");
        Assert.Equal(passkeyId, passkey.Id);
        Assert.Equal("Windows Hello", passkey.FriendlyName);
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
    public async Task AdminEnrollment_WithoutRecentAuthentication_IsForbidden()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        var controller = CreateAdminMfaController(provider, user.Id, authenticatedAt: null);

        Assert.IsType<ForbidResult>(await controller.EnrollmentOptions(CancellationToken.None));
        Assert.IsType<ForbidResult>(await controller.BeginTotp(CancellationToken.None));
    }

    [Fact]
    public async Task AdminEnrollment_WithFreshPasswordLogin_CanStartPasskeyCeremony()
    {
        using var provider = TestUserStoreHost.Create();
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        var controller = CreateAdminMfaController(provider, user.Id, authenticatedAt: DateTimeOffset.UtcNow);

        Assert.IsType<JsonResult>(await controller.EnrollmentOptions(CancellationToken.None));
    }

    [Fact]
    public async Task AdminAssertTotp_IsRateLimitedPerUser()
    {
        var options = new AuthOptions();
        options.RateLimit.MfaChallengeAccountPerMinute = 2;
        using var provider = TestUserStoreHost.Create(options);
        var user = await SeedAdminAsync(provider, emailConfirmed: true);
        await SeedTotpFactorAsync(provider, user.Id);
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
        var factorId = await SeedTotpFactorAsync(provider, user.Id);
        var controller = CreateAdminMfaController(
            provider, user.Id, authenticatedAt: DateTimeOffset.UtcNow, recentMfaMethod: MfaClaimTypes.Totp);

        var result = Assert.IsType<BadRequestObjectResult>(await controller.ConfirmTotp(
            new ConfirmTotpRequest { FactorId = factorId, Code = "000000" }, CancellationToken.None));

        Assert.Contains("验证码错误", result.Value!.ToString(), StringComparison.Ordinal);
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

    private static async Task<Guid> SeedTotpFactorAsync(ServiceProvider provider, string userId)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var factorId = Guid.NewGuid();
        var protector = new TotpSecretProtector(
            Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1");
        var protectedSecret = protector.Protect(userId, factorId, System.Security.Cryptography.RandomNumberGenerator.GetBytes(20));
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

    private static MfaController CreateAdminMfaController(
        ServiceProvider provider, string userId, DateTimeOffset? authenticatedAt, string? recentMfaMethod = null)
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
        var totp = new TotpFactorService(db,
            new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System);
        return new MfaController(
            provider.GetRequiredService<UserService>(),
            new WebAuthnCeremonyService(new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                db, new MfaChallengeStore(db, TimeProvider.System)),
            totp,
            provider.GetRequiredService<LoginSessionService>(),
            db,
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            new MfaService(db, provider.GetRequiredService<UserService>(), totp,
                provider.GetRequiredService<LoginSessionService>(), TimeProvider.System))
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
    }

    private static MfaController CreateUserMfaController(ServiceProvider provider, string userId)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId)], LoginSessionService.Scheme));
        var totp = new TotpFactorService(db,
            new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System);
        return new MfaController(
            provider.GetRequiredService<UserService>(),
            new WebAuthnCeremonyService(new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                db, new MfaChallengeStore(db, TimeProvider.System)),
            totp,
            provider.GetRequiredService<LoginSessionService>(),
            db,
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>(),
            provider.GetRequiredService<LoginRateLimiter>(),
            new MfaService(db, provider.GetRequiredService<UserService>(), totp,
                provider.GetRequiredService<LoginSessionService>(), TimeProvider.System))
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
    }
}
