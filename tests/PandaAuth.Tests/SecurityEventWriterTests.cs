using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SecurityEventWriterTests
{
    [Fact]
    public async Task RecordAsync_PersistsSecurityContextAndSerializesMetadata()
    {
        await using var db = CreateDb();
        var writer = new SecurityEventWriter(db, TimeProvider.System);

        await writer.RecordAsync(new SecurityEventEntry(
            EventType: "user.password_changed",
            UserId: "user-1",
            ActorUserId: "admin-1",
            TargetType: "user",
            TargetId: "user-1",
            AuthenticationMethod: "WebAuthn",
            Metadata: new { generated = false, source = "admin" },
            IpAddress: "203.0.113.10",
            UserAgent: "test-agent",
            CorrelationId: "request-1"));

        var saved = await db.SecurityEvents.SingleAsync();
        Assert.Equal("user.password_changed", saved.EventType);
        Assert.Equal("user-1", saved.UserId);
        Assert.Equal("admin-1", saved.ActorUserId);
        Assert.Equal("user", saved.TargetType);
        Assert.Equal("user-1", saved.TargetId);
        Assert.Equal("WebAuthn", saved.AuthenticationMethod);
        Assert.Equal("203.0.113.10", saved.IpAddress);
        Assert.Equal("test-agent", saved.UserAgent);
        Assert.Equal("request-1", saved.CorrelationId);
        Assert.Contains("\"generated\":false", saved.Metadata);
        Assert.Contains("\"source\":\"admin\"", saved.Metadata);
        Assert.NotEqual(default, saved.CreatedAt);
    }

    [Fact]
    public async Task RecordAsync_AllowsOptionalContextWithoutInventingValues()
    {
        await using var db = CreateDb();
        var writer = new SecurityEventWriter(db, TimeProvider.System);

        await writer.RecordAsync(new SecurityEventEntry(
            EventType: "account.login",
            UserId: "user-1",
            ActorUserId: null,
            TargetType: null,
            TargetId: null,
            AuthenticationMethod: null,
            Metadata: null,
            IpAddress: null,
            UserAgent: null,
            CorrelationId: null));

        var saved = await db.SecurityEvents.SingleAsync();
        Assert.Null(saved.ActorUserId);
        Assert.Null(saved.TargetType);
        Assert.Null(saved.Metadata);
        Assert.Null(saved.CorrelationId);
    }

    private static PandaAuthDbContext CreateDb()
        => new(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options);
}
