using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public class AccountVerificationServiceTests
{
    private sealed class FakeTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-09-21T09:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        private static readonly Regex TokenPattern = new("[A-Za-z0-9_-]{43}", RegexOptions.Compiled);
        public ConcurrentQueue<(string Email, string Subject, string Body)> Messages { get; } = new();

        public Task SendVerificationCodeAsync(string email, string code, CancellationToken ct)
            => throw new InvalidOperationException("The legacy OTP path must not be used.");

        public Task SendAsync(string email, string subject, string htmlBody, CancellationToken ct)
        {
            Messages.Enqueue((email, subject, htmlBody));
            return Task.CompletedTask;
        }

        public string TakeToken()
        {
            Assert.True(Messages.TryDequeue(out var message));
            return Assert.Single(TokenPattern.Matches(message.Body).Select(match => match.Value));
        }
    }

    private sealed record TestHost(ServiceProvider Provider, FakeTimeProvider Time, RecordingEmailSender Email)
        : IAsyncDisposable
    {
        public async ValueTask DisposeAsync() => await Provider.DisposeAsync();
    }

    private static TestHost CreateHost()
    {
        var time = new FakeTimeProvider();
        var email = new RecordingEmailSender();
        var databaseName = Guid.NewGuid().ToString("N");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(time);
        services.AddSingleton<IEmailSender>(email);
        services.AddDbContext<PandaAuthDbContext>(options =>
            options.UseInMemoryDatabase(databaseName));
        services.AddUserStore();
        services.AddScoped<AccountVerificationService>();
        return new TestHost(services.BuildServiceProvider(), time, email);
    }

    private static async Task<PandaUser> SeedUserAsync(
        IServiceProvider provider,
        string email = "user@example.com",
        bool emailConfirmed = true)
    {
        using var scope = provider.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        var user = new PandaUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = emailConfirmed,
        };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        return user;
    }

    [Fact]
    public async Task EmailConfirmationToken_CannotBeUsedForEmailChange()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider, emailConfirmed: false);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();

        Assert.True((await service.BeginEmailConfirmationAsync(user.Id)).Succeeded);
        var token = host.Email.TakeToken();

        var wrongPurpose = await service.ConsumeEmailChangeAsync(user.Id, "new@example.com", token);
        Assert.False(wrongPurpose.Succeeded);
        Assert.Equal(AccountVerificationError.InvalidOrExpiredToken, wrongPurpose.Error);
        Assert.True((await service.ConsumeEmailConfirmationAsync(user.Id, token)).Succeeded);
    }

    [Fact]
    public async Task Issuance_StoresOnlyTokenHash_WithPurposeSubjectTargetAndExpiry()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider, emailConfirmed: false);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();

        await service.BeginEmailConfirmationAsync(user.Id);
        var token = host.Email.TakeToken();
        var row = Assert.Single(await db.EmailVerifications.AsNoTracking().ToListAsync());

        Assert.Equal(AccountVerificationPurpose.EmailConfirmation, row.Purpose);
        Assert.Equal(user.Id, row.SubjectId);
        Assert.Equal("USER@EXAMPLE.COM", row.NormalizedTarget);
        Assert.Equal(VerificationHasher.TokenHash(token), row.TokenHash);
        Assert.NotEqual(token, row.TokenHash);
        Assert.Equal(host.Time.Now.AddMinutes(AccountVerificationService.TokenTtlMinutes), row.ExpiresAt);
        Assert.DoesNotContain(token, row.GetType().GetProperties()
            .Where(property => property.PropertyType == typeof(string))
            .Select(property => property.GetValue(row) as string));
    }

    [Fact]
    public async Task ExpiredPasswordResetToken_IsRejected()
    {
        await using var host = CreateHost();
        await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        await service.BeginPasswordResetAsync("user@example.com");
        var token = host.Email.TakeToken();

        host.Time.Now = host.Time.Now.AddMinutes(AccountVerificationService.TokenTtlMinutes + 1);
        var result = await service.ConsumePasswordResetAsync(
            "user@example.com", token, "NewStrong!Pass456");

        Assert.False(result.Succeeded);
        Assert.Equal(AccountVerificationError.InvalidOrExpiredToken, result.Error);
    }

    [Fact]
    public async Task PasswordResetToken_IsSingleUse_AndRotatesSecurityStamp()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider);
        var stampBefore = user.SecurityStamp;
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        await service.BeginPasswordResetAsync("user@example.com");
        var token = host.Email.TakeToken();

        var first = await service.ConsumePasswordResetAsync(
            "USER@example.com", token, "NewStrong!Pass456");
        var replay = await service.ConsumePasswordResetAsync(
            "user@example.com", token, "Another!Pass789");
        var reloaded = await users.FindByIdAsync(user.Id);

        Assert.True(first.Succeeded);
        Assert.Equal(AccountSecurityEvent.PasswordReset, first.SecurityEvent?.Type);
        Assert.False(replay.Succeeded);
        Assert.NotEqual(stampBefore, reloaded!.SecurityStamp);
        Assert.True(await users.CheckPasswordAsync(reloaded, "NewStrong!Pass456"));
        Assert.False(await users.CheckPasswordAsync(reloaded, "Another!Pass789"));
    }

    [Fact]
    public async Task ConcurrentEmailConfirmation_AllowsExactlyOneConsumer()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider, emailConfirmed: false);
        using (var issueScope = host.Provider.CreateScope())
        {
            await issueScope.ServiceProvider.GetRequiredService<AccountVerificationService>()
                .BeginEmailConfirmationAsync(user.Id);
        }
        var token = host.Email.TakeToken();

        using var firstScope = host.Provider.CreateScope();
        using var secondScope = host.Provider.CreateScope();
        var results = await Task.WhenAll(
            firstScope.ServiceProvider.GetRequiredService<AccountVerificationService>()
                .ConsumeEmailConfirmationAsync(user.Id, token),
            secondScope.ServiceProvider.GetRequiredService<AccountVerificationService>()
                .ConsumeEmailConfirmationAsync(user.Id, token));

        Assert.Single(results, result => result.Succeeded);
        Assert.Single(results, result => !result.Succeeded);
    }

    [Fact]
    public async Task UnknownAndUnconfirmedPasswordResetRequests_ReturnSameNeutralResult()
    {
        await using var host = CreateHost();
        await SeedUserAsync(host.Provider, emailConfirmed: false);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();

        var unconfirmed = await service.BeginPasswordResetAsync("user@example.com");
        var unknown = await service.BeginPasswordResetAsync("missing@example.com");

        Assert.True(unconfirmed.Succeeded);
        Assert.True(unknown.Succeeded);
        Assert.Null(unconfirmed.Error);
        Assert.Null(unknown.Error);
        Assert.Empty(host.Email.Messages);
        Assert.Equal(2, await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>()
            .PasswordResetRequests.CountAsync());
    }

    [Fact]
    public async Task RepeatedPasswordResetRequest_StaysNeutralWithoutIssuingAgainWithinOneMinute()
    {
        await using var host = CreateHost();
        await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();

        var first = await service.BeginPasswordResetAsync("user@example.com");
        var second = await service.BeginPasswordResetAsync("USER@example.com");

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
        Assert.Single(host.Email.Messages);
        Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>()
            .PasswordResetRequests.CountAsync());
    }

    [Fact]
    public async Task NewPasswordResetToken_RevokesEarlierTokenEvenAfterNewestIsUsed()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();

        await service.BeginPasswordResetAsync("user@example.com");
        var firstToken = host.Email.TakeToken();
        host.Time.Now = host.Time.Now.AddMinutes(2);
        await service.BeginPasswordResetAsync("user@example.com");
        var secondToken = host.Email.TakeToken();

        Assert.True((await service.ConsumePasswordResetAsync(
            "user@example.com", secondToken, "NewStrong!Pass456")).Succeeded);
        Assert.False((await service.ConsumePasswordResetAsync(
            "user@example.com", firstToken, "Another!Pass789")).Succeeded);
        Assert.True(await users.CheckPasswordAsync((await users.FindByIdAsync(user.Id))!, "NewStrong!Pass456"));
    }

    [Fact]
    public async Task RepeatedEmailConfirmation_DoesNotSendOrIssueAgainWithinOneMinute()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider, emailConfirmed: false);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();

        Assert.True((await service.BeginEmailConfirmationAsync(user.Id)).Succeeded);
        Assert.True((await service.BeginEmailConfirmationAsync(user.Id)).Succeeded);

        Assert.Single(host.Email.Messages);
        Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>()
            .EmailVerifications.CountAsync());
    }

    [Fact]
    public async Task EmailChange_RequiresConfirmedSourceAndLeavesAddressUnchangedUntilProof()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider, emailConfirmed: false);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();

        var rejected = await service.BeginEmailChangeAsync(user.Id, "new@example.com");
        Assert.Equal(AccountVerificationError.EmailNotConfirmed, rejected.Error);
        Assert.Empty(host.Email.Messages);
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        var tracked = (await users.FindByIdAsync(user.Id))!;
        tracked.EmailConfirmed = true;
        Assert.True((await users.UpdateAsync(tracked)).Succeeded);

        Assert.True((await service.BeginEmailChangeAsync(user.Id, "new@example.com")).Succeeded);
        Assert.Equal("user@example.com", (await users.FindByIdAsync(user.Id))!.Email);
        var token = host.Email.TakeToken();
        Assert.True((await service.ConsumeEmailChangeAsync(user.Id, "new@example.com", token)).Succeeded);
        Assert.Equal("new@example.com", (await users.FindByIdAsync(user.Id))!.Email);
    }

    [Fact]
    public async Task FiveWrongAttempts_BlockTheCorrectToken()
    {
        await using var host = CreateHost();
        await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        await service.BeginPasswordResetAsync("user@example.com");
        var token = host.Email.TakeToken();

        for (var attempt = 0; attempt < AccountVerificationService.MaxAttempts; attempt++)
        {
            var wrong = await service.ConsumePasswordResetAsync(
                "user@example.com", $"wrong-{attempt}", "NewStrong!Pass456");
            Assert.False(wrong.Succeeded);
        }

        var blocked = await service.ConsumePasswordResetAsync(
            "user@example.com", token, "NewStrong!Pass456");
        Assert.False(blocked.Succeeded);
        Assert.Equal(AccountVerificationError.TooManyAttempts, blocked.Error);
    }

    [Fact]
    public async Task Retention_RemovesExpiredTokensButKeepsActiveTokens()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider, emailConfirmed: false);
        using var scope = host.Provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        await service.BeginEmailConfirmationAsync(user.Id);
        await service.BeginPasswordResetAsync("missing@example.com");
        db.EmailVerifications.Add(new EmailVerification
        {
            SubjectId = user.Id,
            NormalizedTarget = "USER@EXAMPLE.COM",
            TokenHash = "expired-email",
            CreatedAt = host.Time.Now.AddDays(-3),
            ExpiresAt = host.Time.Now.AddDays(-3).AddMinutes(20),
        });
        db.PasswordResetRequests.Add(new PasswordResetRequest
        {
            NormalizedTarget = "OLD@EXAMPLE.COM",
            TokenHash = "expired-reset",
            CreatedAt = host.Time.Now.AddDays(-3),
            ExpiresAt = host.Time.Now.AddDays(-3).AddMinutes(20),
        });
        await db.SaveChangesAsync();

        var removed = await LoginLogRetentionService.PurgeAccountVerificationTokensAsync(
            db, host.Time.Now, CancellationToken.None);

        Assert.Equal(2, removed);
        Assert.Single(await db.EmailVerifications.ToListAsync());
        Assert.Single(await db.PasswordResetRequests.ToListAsync());
    }

    [Fact]
    public async Task DuplicateEmailAtConsumption_DoesNotLeakRejectedChangesIntoLaterSave()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        await service.BeginEmailChangeAsync(user.Id, "taken@example.com");
        var token = host.Email.TakeToken();
        await SeedUserAsync(host.Provider, "taken@example.com");

        var rejected = await service.ConsumeEmailChangeAsync(user.Id, "taken@example.com", token);
        Assert.Equal(AccountVerificationError.DuplicateEmail, rejected.Error);
        await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().SaveChangesAsync();
        using var read = host.Provider.CreateScope();
        var persisted = await read.ServiceProvider.GetRequiredService<UserService>().FindByIdAsync(user.Id);
        Assert.Equal("user@example.com", persisted!.Email);
        Assert.Equal(user.SecurityStamp, persisted.SecurityStamp);
    }

    [Fact]
    public async Task NewEmailChange_SupersedesPendingProofForAnotherTarget()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        await service.BeginEmailChangeAsync(user.Id, "first@example.com");
        var first = host.Email.TakeToken();
        host.Time.Now = host.Time.Now.AddMinutes(2);
        await service.BeginEmailChangeAsync(user.Id, "second@example.com");
        var second = host.Email.TakeToken();

        Assert.True((await service.ConsumeEmailChangeAsync(user.Id, "second@example.com", second)).Succeeded);
        Assert.False((await service.ConsumeEmailChangeAsync(user.Id, "first@example.com", first)).Succeeded);
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("name@example.com\r\nBcc:other@example.com")]
    public async Task InvalidEmailChangeTarget_IsRejectedWithoutIssuing(string target)
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        Assert.Equal(AccountVerificationError.InvalidTarget,
            (await service.BeginEmailChangeAsync(user.Id, target)).Error);
        Assert.Empty(host.Email.Messages);
    }

    [Fact]
    public async Task EmailChange_TrimsTargetConsistentlyForIssuanceAndConsumption()
    {
        await using var host = CreateHost();
        var user = await SeedUserAsync(host.Provider);
        using var scope = host.Provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<AccountVerificationService>();
        await service.BeginEmailChangeAsync(user.Id, " new@example.com ");
        Assert.True((await service.ConsumeEmailChangeAsync(
            user.Id, " new@example.com ", host.Email.TakeToken())).Succeeded);
    }
}
