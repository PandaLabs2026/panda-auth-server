using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using PandaAuth.Server.Features.SessionState;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SsoSessionApiTests
{
    [Fact]
    public async Task DedicatedClients_ShareLoginRevocation_ButLegacyClientPartitionsRemainIsolated()
    {
        await using var db = Database();
        var controller = Controller(db, PandaAuthSessionApi.AdminClientId);
        const string sid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        Assert.IsType<NoContentResult>(await controller.RevokeSso(new(sid), default));
        controller.HttpContext.User = Principal(PandaAuthSessionApi.MeClientId);
        var result = Assert.IsType<OkObjectResult>((await controller.CheckSso(new(sid), default)).Result);
        Assert.True(Assert.IsType<SessionStateCheckResponse>(result.Value).Revoked);
        var local = Assert.IsType<OkObjectResult>((await controller.Check(new(sid), default)).Result);
        Assert.False(Assert.IsType<SessionStateCheckResponse>(local.Value).Revoked);
    }
    [Fact]
    public async Task DefaultOff_BlocksNewSharedWrites_ButStillReadsExistingRevocations()
    {
        await using var db = Database();
        var revocations = new SessionRevocationService(db, TimeProvider.System);
        const string oldSid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", newSid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        await revocations.RevokeAsync(PandaAuthSessionApi.SsoPartition, oldSid, default);
        var controller = new SessionStateController(revocations)
        { ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext { User = Principal(PandaAuthSessionApi.AdminClientId) } } };
        Assert.Equal(503, Assert.IsType<StatusCodeResult>(await controller.RevokeSso(new(newSid), default)).StatusCode);
        Assert.False(await revocations.IsRevokedAsync(PandaAuthSessionApi.SsoPartition, newSid, default));
        var result = Assert.IsType<OkObjectResult>((await controller.CheckSso(new(oldSid), default)).Result);
        Assert.True(Assert.IsType<SessionStateCheckResponse>(result.Value).Revoked);
        Assert.IsType<NoContentResult>(await controller.Revoke(new(newSid), default));
    }
    [Theory]
    [InlineData("fleet-api", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
    [InlineData("sso-session", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
    [InlineData("admin-session-api", "not-a-session-id", false)]
    [InlineData("me-session-api", "", false)]
    public async Task UnauthorizedClientsAndMalformedIds_AreRejected(string client, string sid, bool forbidden)
    {
        await using var db = Database();
        var result = await Controller(db, client).RevokeSso(new(sid), default);
        if (forbidden) Assert.IsType<ForbidResult>(result); else Assert.IsType<BadRequestResult>(result);
        Assert.Empty(db.SessionRevocations);
    }
    private static PandaAuthDbContext Database() => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);
    private static ClaimsPrincipal Principal(string client) => new(new ClaimsIdentity([new Claim("client_id", client)], "verified"));
    private static SessionStateController Controller(PandaAuthDbContext db, string client) => new(new(db, TimeProvider.System), new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string?> { [PandaAuthSessionApi.SharedLogoutEnabled] = "true" }).Build())
    { ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext { User = Principal(client) } } };
}
