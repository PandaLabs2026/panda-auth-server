using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class SecurityRetentionTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Defaults_Are_Disabled_And_Do_Not_Create_A_Database_Scope()
    {
        var options = new AuthOptions();
        Assert.False(options.Retention.Enabled);
        Assert.Equal(90, options.Retention.SecurityEventRetentionDays);
        Assert.Equal(14, options.Retention.TokenRetentionDays);
        var factory = new RejectingScopeFactory();
        var service = new SecurityDataRetentionService(factory, Options.Create(options), new CaptureLogger(), TimeProvider.System);
        Assert.Equal(new RetentionCounts(0, 0), await service.RunOnceAsync(CancellationToken.None));
        Assert.Equal(0, factory.Calls);
        Assert.Equal(500, SecurityDataRetentionService.BatchSize);
        Assert.Equal(5000, SecurityDataRetentionService.MaxPerRun);
        Assert.Equal(TimeSpan.FromHours(24), SecurityDataRetentionService.Interval);
    }

    [Theory]
    [InlineData(89, 14)]
    [InlineData(90, 13)]
    [InlineData(3651, 14)]
    [InlineData(90, 3651)]
    public void Enabled_Configuration_Rejects_Unsafe_Ranges(int events, int tokens)
    {
        var options = new AuthRetentionOptions { Enabled = true, SecurityEventRetentionDays = events, TokenRetentionDays = tokens };
        Assert.Throws<InvalidOperationException>(() => options.Validate());
        options.Enabled = false;
        options.Validate();
    }

    [Fact]
    public void Security_Events_Use_A_Strict_Cutoff()
    {
        var cutoff = Now.AddDays(-90);
        var eligible = SecurityRetentionPolicy.EventsBefore(cutoff).Compile();
        Assert.True(eligible(new SecurityEvent { CreatedAt = cutoff.AddTicks(-1) }));
        Assert.False(eligible(new SecurityEvent { CreatedAt = cutoff }));
        Assert.False(eligible(new SecurityEvent { CreatedAt = Now }));
    }

    [Theory]
    [InlineData("expired", true)]
    [InlineData("old-revoked", true)]
    [InlineData("old-redeemed", true)]
    [InlineData("unexpired-revoked", false)]
    [InlineData("missing-expiry", false)]
    [InlineData("missing-creation", false)]
    [InlineData("missing-redemption", false)]
    [InlineData("fresh-creation", false)]
    [InlineData("fresh-redemption", false)]
    [InlineData("boundary", false)]
    public void Token_Cleanup_Preserves_Replay_And_Uncertain_Timestamps(string scenario, bool expected)
    {
        var cutoff = Now.AddDays(-14).UtcDateTime;
        var token = new OpenIddictEntityFrameworkCoreToken { Status = Statuses.Valid, CreationDate = cutoff.AddDays(-1), ExpirationDate = cutoff.AddDays(-1) };
        switch (scenario)
        {
            case "old-revoked": token.Status = Statuses.Revoked; break;
            case "old-redeemed": token.Status = Statuses.Redeemed; token.RedemptionDate = cutoff.AddDays(-1); break;
            case "unexpired-revoked": token.Status = Statuses.Revoked; token.ExpirationDate = Now.UtcDateTime.AddDays(1); break;
            case "missing-expiry": token.ExpirationDate = null; break;
            case "missing-creation": token.CreationDate = null; break;
            case "missing-redemption": token.Status = Statuses.Redeemed; break;
            case "fresh-creation": token.CreationDate = Now.UtcDateTime; break;
            case "fresh-redemption": token.Status = Statuses.Redeemed; token.RedemptionDate = Now.UtcDateTime; break;
            case "boundary": token.ExpirationDate = cutoff; break;
        }
        Assert.Equal(expected, SecurityRetentionPolicy.TokensBefore(cutoff).Compile()(token));
    }

    [Fact]
    public async Task Cancellation_Does_Not_Open_A_Database_Scope()
    {
        var options = new AuthOptions(); options.Retention.Enabled = true;
        var factory = new RejectingScopeFactory();
        var service = new SecurityDataRetentionService(factory, Options.Create(options), new CaptureLogger(), TimeProvider.System);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.RunOnceAsync(new CancellationToken(true)));
        Assert.Equal(0, factory.Calls);
    }

    [Fact]
    public async Task Failure_Logs_Class_Without_Exception_Details_Or_Secrets()
    {
        var options = new AuthOptions(); options.Retention.Enabled = true;
        var logger = new CaptureLogger();
        var service = new SecurityDataRetentionService(new RejectingScopeFactory(), Options.Create(options), logger, TimeProvider.System);
        await service.RunCycleAsync(CancellationToken.None);
        Assert.Contains(nameof(InvalidOperationException), string.Join("", logger.Messages));
        Assert.DoesNotContain("fixture-secret-sentinel", string.Join("", logger.Messages));
        Assert.False(logger.HadExceptionArgument);
    }

    private sealed class RejectingScopeFactory : IServiceScopeFactory
    {
        internal int Calls;
        public IServiceScope CreateScope() { Calls++; throw new InvalidOperationException("fixture-secret-sentinel"); }
    }
    private sealed class CaptureLogger : ILogger<SecurityDataRetentionService>
    {
        internal List<string> Messages { get; } = [];
        internal bool HadExceptionArgument;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        { HadExceptionArgument |= exception is not null; Messages.Add(formatter(state, exception)); }
    }
}
