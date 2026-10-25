using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class AdminSecurityAtomicityTests
{
    [PostgresTheory]
    [InlineData("status", false)]
    [InlineData("password", false)]
    [InlineData("roles", false)]
    [InlineData("deactivate", false)]
    [InlineData("mfa", false)]
    [InlineData("status", true)]
    [InlineData("password", true)]
    [InlineData("roles", true)]
    [InlineData("deactivate", true)]
    [InlineData("mfa", true)]
    public async Task SecurityFailure_RollsBackAccountMembershipTokensAndAudit(string operation, bool auditFailure)
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(services =>
        {
            if (!auditFailure)
            {
                services.RemoveAll<ITokenRevoker>();
                services.AddScoped<ITokenRevoker, FailingRevoker>();
            }
        });
        string targetId, stamp, passwordHash;
        using (var setup = fixture.Host.Services.CreateScope())
        {
            var users = setup.ServiceProvider.GetRequiredService<UserService>();
            var target = new PandaUser { UserName = "atomic-target", Email = "atomic-target@example.test", EmailConfirmed = true, TwoFactorEnabled = true };
            Assert.True((await users.CreateAsync(target, "Before!Password123")).Succeeded);
            targetId = target.Id; stamp = target.SecurityStamp!; passwordHash = target.PasswordHash!;
        }
        await using (var db = fixture.Context())
        {
            db.Set<OpenIddictEntityFrameworkCoreToken>().Add(new()
            { Id = Guid.NewGuid().ToString(), Subject = targetId, Status = "valid", Type = "access_token" });
            await db.SaveChangesAsync();
            if (auditFailure)
                await db.Database.ExecuteSqlRawAsync("""
                    CREATE FUNCTION fail_security_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
                    CREATE TRIGGER fail_security_audit BEFORE INSERT ON panda_security_events
                    FOR EACH ROW EXECUTE FUNCTION fail_security_audit();
                    """);
        }
        using (var request = fixture.Host.Services.CreateScope())
        {
            var controller = ActivatorUtilities.CreateInstance<AdminUsersController>(request.ServiceProvider);
            controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext
            {
                RequestServices = request.ServiceProvider,
                User = new ClaimsPrincipal(new ClaimsIdentity([
                    new Claim("sub", fixture.UserId), new Claim("role", "admin"),
                    new Claim(MfaClaimTypes.Method, MfaClaimTypes.WebAuthn),
                    new Claim(MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                ], "verified")),
            }};
            await Assert.ThrowsAnyAsync<Exception>(() => operation switch
            {
                "status" => controller.SetStatus(targetId, new AdminUserStatusRequest(UserStatus.Frozen), default),
                "password" => controller.ResetPassword(targetId, new AdminResetPasswordRequest("Changed!Password123"), default),
                "roles" => controller.UpdateRoles(targetId, new AdminUserRolesRequest([PandaAuthRoles.Admin]), default),
                "mfa" => controller.ResetTwoFactor(targetId, default),
                _ => controller.Deactivate(targetId, new AdminDeactivateRequest("atomic-target"), default),
            });
        }
        await using var verify = fixture.Context();
        var persisted = await verify.Users.SingleAsync(user => user.Id == targetId);
        Assert.Equal(UserStatus.Active, persisted.Status);
        Assert.True(persisted.TwoFactorEnabled);
        Assert.Equal(stamp, persisted.SecurityStamp);
        Assert.Equal(passwordHash, persisted.PasswordHash);
        Assert.Empty(await verify.UserRoles.Where(role => role.UserId == targetId).ToArrayAsync());
        Assert.Equal("valid", (await verify.Set<OpenIddictEntityFrameworkCoreToken>().SingleAsync(token => token.Subject == targetId)).Status);
        Assert.Empty(await verify.AdminAuditLogs.ToArrayAsync());
        Assert.Empty(await verify.SecurityEvents.ToArrayAsync());
    }

    private sealed class FailingRevoker : ITokenRevoker
    {
        public Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
            => throw new OperationCanceledException("injected revocation cancellation");
        public Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
            => throw new OperationCanceledException();
    }
}
