using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using PandaAuth.Server.Features.SessionState;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SsoTokenValidationTests
{
    [Theory]
    [InlineData("human", true)]
    [InlineData("machine", false)]
    public async Task LegacyHumanTokenRequiresReauthentication_MachineTokenIsUnaffected(string kind, bool rejected)
    {
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);
        var context = new OpenIddictServerEvents.ProcessAuthenticationContext(new OpenIddictServerTransaction
        { Request = new OpenIddictRequest() })
        { AccessTokenPrincipal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(PandaAuthClaims.SubjectType, kind)], "verified")) };
        await new RejectRevokedSsoSession(new(db, TimeProvider.System)).HandleAsync(context);
        Assert.Equal(rejected, context.IsRejected);
    }

    [Fact]
    public async Task ResourceApiBearer_CannotBypassCentralRevocation()
    {
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);
        var service = new SessionRevocationService(db, TimeProvider.System);
        const string sid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        await service.RevokeAsync(PandaAuthSessionApi.SsoPartition, sid, default);
        var context = new OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext(
            new OpenIddict.Validation.OpenIddictValidationTransaction())
        { AccessTokenPrincipal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(PandaAuthClaims.SsoSessionId, sid)], "verified")) };
        await new RejectRevokedSsoBearer(service).HandleAsync(context);
        Assert.True(context.IsRejected);
    }

    [Theory]
    [InlineData("access")]
    [InlineData("refresh")]
    [InlineData("code")]
    [InlineData("introspection")]
    public async Task RevokedSession_IsRejectedAcrossValidatedTokenKinds_OtherDeviceRemainsValid(string kind)
    {
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);
        var service = new SessionRevocationService(db, TimeProvider.System);
        const string revoked = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        await service.RevokeAsync(PandaAuthSessionApi.SsoPartition, revoked, default);
        var handler = new RejectRevokedSsoSession(service);
        foreach (var sid in new[] { revoked, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" })
        {
            var context = new OpenIddictServerEvents.ProcessAuthenticationContext(new OpenIddictServerTransaction
            { Request = new OpenIddictRequest() });
            var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(PandaAuthClaims.SsoSessionId, sid)], "verified"));
            switch (kind)
            {
                case "access": context.AccessTokenPrincipal = principal; break;
                case "refresh": context.RefreshTokenPrincipal = principal; break;
                case "code": context.AuthorizationCodePrincipal = principal; break;
                default: context.GenericTokenPrincipal = principal; break;
            }
            await handler.HandleAsync(context);
            Assert.Equal(sid == revoked, context.IsRejected);
        }
    }
}
