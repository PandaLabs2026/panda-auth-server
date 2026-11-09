using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ProfileContactTests
{
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = new(2026, 11, 9, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan interval) => now += interval;
    }
    private sealed class Mail : IEmailSender
    {
        public string Token { get; private set; } = "";
        public Guid DeliveryId { get; private set; }
        public bool Fail { get; init; }
        public Task SendAsync(string email, string subject, string html, CancellationToken ct) => throw new InvalidOperationException("Unexpected legacy mail path");
        public Task SendPasswordResetNoticeAsync(string email, CancellationToken ct) => throw new InvalidOperationException("Unexpected credential mail");
        public Task SendProfileContactVerificationAsync(string email, string token, Guid deliveryId, CancellationToken ct)
        {
            Token = token; DeliveryId = deliveryId;
            return Fail ? Task.FromException(new HttpRequestException("synthetic delivery failure")) : Task.CompletedTask;
        }
    }
    private static (SelfProfileService Profiles, ProfileContactService Contacts) Services(PandaAuthDbContext db, Clock clock, Mail mail)
    {
        var audit = new SecurityEventWriter(db, clock);
        var profiles = new SelfProfileService(db, audit, clock);
        return (profiles, new ProfileContactService(db, profiles, mail, audit, clock));
    }
    private static async Task<PandaUser> User(PandaAuthDbContext db)
    {
        var user = new PandaUser { Email = "login@example.invalid" };
        db.Users.Add(user); await db.SaveChangesAsync(); return user;
    }

    [PostgresFact]
    public async Task Proof_verifies_only_contact_and_is_single_use_without_plaintext_token_storage()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = await User(db); var clock = new Clock(); var mail = new Mail();
        var (_, contacts) = Services(db, clock, mail);
        var pending = await contacts.CreateAsync(user.Id, "\"0\"", "Contact+tag@Example.invalid", "contact-test");
        Assert.Equal(ProfileContactEmailState.Pending, pending.Profile.ContactEmail.State);
        Assert.Equal(43, mail.Token.Length);
        var challenge = await db.ProfileContactChallenges.AsNoTracking().SingleAsync();
        Assert.Equal(32, challenge.TokenDigest.Length);
        Assert.Equal(mail.DeliveryId, challenge.DeliveryId);
        var verified = await contacts.ConfirmAsync(user.Id, pending.ChallengeId, mail.Token, "contact-test");
        Assert.Equal(ProfileContactEmailState.Verified, verified.ContactEmail.State);
        Assert.Equal("Contact+tag@Example.invalid", verified.ContactEmail.Address);
        Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(user.Id, pending.ChallengeId, mail.Token, "contact-test"))).StatusCode);
        db.ChangeTracker.Clear();
        var login = await db.Users.SingleAsync();
        Assert.Equal("login@example.invalid", login.Email);
        Assert.False(login.EmailConfirmed);
        foreach (var audit in await db.SecurityEvents.ToListAsync())
        {
            Assert.DoesNotContain(mail.Token, audit.Metadata ?? "");
            Assert.DoesNotContain("Contact+tag@Example.invalid", audit.Metadata ?? "");
        }
    }

    [PostgresFact]
    public async Task Expired_or_wrong_proofs_and_account_rate_limits_survive_new_contexts()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        var clock = new Clock(); var mail = new Mail(); string id; ProfileContactEmailChallengeResponse pending;
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            id = (await User(db)).Id;
            pending = await Services(db, clock, mail).Contacts.CreateAsync(id, "\"0\"", "pending@example.invalid", "contact-test");
        }
        for (var attempt = 0; attempt < 5; attempt++)
        {
            await using var scope = fixture.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var error = await Assert.ThrowsAsync<ProfileOperationException>(() => Services(db, clock, mail).Contacts.ConfirmAsync(id, pending.ChallengeId, new string('A', 43), "contact-test"));
            Assert.Equal(422, error.StatusCode);
        }
        await using var check = fixture.Services.CreateAsyncScope();
        var current = check.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(5, (await current.ProfileContactChallenges.AsNoTracking().SingleAsync()).FailedAttempts);
        Assert.Equal(ProfileContactChallengeState.Failed, (await current.ProfileContactChallenges.AsNoTracking().SingleAsync()).State);
        var contacts = Services(current, clock, mail).Contacts;
        Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(id, pending.ChallengeId, mail.Token, "contact-test"))).StatusCode);
        for (var attempt = 0; attempt < 4; attempt++)
            Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(id, Guid.NewGuid().ToString("D"), mail.Token, "contact-test"))).StatusCode);
        Assert.Equal(429, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(id, pending.ChallengeId, mail.Token, "contact-test"))).StatusCode);
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(id, pending.ChallengeId, mail.Token, "contact-test"))).StatusCode);
        Assert.Equal(ProfileContactEmailState.Pending, (await Services(current, clock, mail).Profiles.ReadAsync(id)).ContactEmail.State);
        var fresh = await contacts.CreateAsync(id, pending.Profile.Revision, "fresh@example.invalid", "contact-test");
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(id, fresh.ChallengeId, mail.Token, "contact-test"))).StatusCode);
        Assert.Equal(ProfileContactChallengeState.Expired,
            (await current.ProfileContactChallenges.AsNoTracking().SingleAsync(c => c.Id == Guid.Parse(fresh.ChallengeId))).State);
    }

    [PostgresFact]
    public async Task Profile_edits_supersede_pending_challenges_and_another_actor_cannot_consume_them()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = await User(db); var other = await User(db); var clock = new Clock(); var mail = new Mail();
        var (profiles, contacts) = Services(db, clock, mail);
        var pending = await contacts.CreateAsync(user.Id, "\"0\"", "first@example.invalid", "contact-test");
        Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(other.Id, pending.ChallengeId, mail.Token, "contact-test"))).StatusCode);
        Assert.Equal(ProfileContactChallengeState.Delivered, (await db.ProfileContactChallenges.AsNoTracking().SingleAsync()).State);
        var revised = await profiles.PatchAsync(user.Id, pending.Profile.Revision, SelfProfileInput.ParsePatch("{\"biography\":\"changed\"}"), "contact-test");
        Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(user.Id, pending.ChallengeId, mail.Token, "contact-test"))).StatusCode);
        Assert.Equal(ProfileContactChallengeState.Superseded, (await db.ProfileContactChallenges.AsNoTracking().SingleAsync()).State);
        clock.Advance(TimeSpan.FromSeconds(61));
        var replacement = await contacts.CreateAsync(user.Id, revised.Revision, "second@example.invalid", "contact-test");
        var verified = await contacts.ConfirmAsync(user.Id, replacement.ChallengeId, mail.Token, "contact-test");
        Assert.Equal("second@example.invalid", verified.ContactEmail.Address);
        clock.Advance(TimeSpan.FromSeconds(61));
        var replacingVerified = await contacts.CreateAsync(user.Id, verified.Revision, "third@example.invalid", "contact-test");
        Assert.Equal(ProfileContactEmailState.Pending, replacingVerified.Profile.ContactEmail.State);
        Assert.Equal("third@example.invalid", replacingVerified.Profile.ContactEmail.Address);
    }

    [PostgresFact]
    public async Task Unconfirmed_delivery_keeps_pending_and_never_verifies()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = await User(db); var clock = new Clock(); var mail = new Mail { Fail = true };
        var (profiles, contacts) = Services(db, clock, mail);
        var error = await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.CreateAsync(user.Id, "\"0\"", "pending@example.invalid", "contact-test"));
        Assert.Equal(503, error.StatusCode);
        var profile = await profiles.ReadAsync(user.Id);
        Assert.Equal(ProfileContactEmailState.Pending, profile.ContactEmail.State);
        var challenge = await db.ProfileContactChallenges.AsNoTracking().SingleAsync();
        Assert.Equal(ProfileContactChallengeState.PendingDelivery, challenge.State);
        Assert.Equal(422, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.ConfirmAsync(user.Id, challenge.Id.ToString("D"), mail.Token, "contact-test"))).StatusCode);
    }
    [PostgresFact]
    public async Task Creation_limits_are_account_wide_and_contact_deletion_does_not_reset_them()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var user = await User(db); var clock = new Clock(); var mail = new Mail();
        var (profiles, contacts) = Services(db, clock, mail);
        var current = await contacts.CreateAsync(user.Id, "\"0\"", "pending@example.invalid", "contact-test");
        Assert.Equal(429, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.CreateAsync(user.Id,
            current.Profile.Revision, "next@example.invalid", "contact-test"))).StatusCode);
        for (var i = 1; i < 5; i++)
        {
            clock.Advance(TimeSpan.FromSeconds(61));
            current = await contacts.CreateAsync(user.Id, current.Profile.Revision, "pending@example.invalid", "contact-test");
        }
        var deleted = await contacts.DeleteAsync(user.Id, current.Profile.Revision, "contact-test");
        Assert.Equal(ProfileContactEmailState.None, deleted.ContactEmail.State);
        Assert.Null(deleted.ContactEmail.Address);
        Assert.Empty(await db.ProfileContactChallenges.AsNoTracking().ToListAsync());
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(429, (await Assert.ThrowsAsync<ProfileOperationException>(() => contacts.CreateAsync(user.Id,
            deleted.Revision, "pending@example.invalid", "contact-test"))).StatusCode);
    }

    private sealed class PausedMail : IEmailSender
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int calls;
        public Task SendAsync(string email, string subject, string html, CancellationToken ct) => throw new InvalidOperationException();
        public Task SendPasswordResetNoticeAsync(string email, CancellationToken ct) => throw new InvalidOperationException();
        public async Task SendProfileContactVerificationAsync(string email, string token, Guid deliveryId, CancellationToken ct)
        {
            if (Interlocked.Increment(ref calls) != 1) return;
            Started.SetResult(); await Release.Task.WaitAsync(ct);
        }
    }

    [PostgresFact]
    public async Task Late_delivery_cannot_resurrect_a_replaced_challenge_or_hold_a_database_transaction()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        var clock = new Clock(); var mail = new PausedMail(); string id;
        await using var firstScope = fixture.Services.CreateAsyncScope();
        var first = firstScope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        id = (await User(first)).Id;
        var firstAudit = new SecurityEventWriter(first, clock);
        var firstProfiles = new SelfProfileService(first, firstAudit, clock);
        var firstContacts = new ProfileContactService(first, firstProfiles, mail, firstAudit, clock);
        var sending = firstContacts.CreateAsync(id, "\"0\"", "old@example.invalid", "contact-test");
        await mail.Started.Task.WaitAsync(TimeSpan.FromSeconds(20));
        try
        {
            Assert.Null(first.Database.CurrentTransaction);
            clock.Advance(TimeSpan.FromSeconds(61));
            await using var secondScope = fixture.Services.CreateAsyncScope();
            var second = secondScope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var secondAudit = new SecurityEventWriter(second, clock);
            var secondProfiles = new SelfProfileService(second, secondAudit, clock);
            var current = await secondProfiles.ReadAsync(id);
            var replacement = await new ProfileContactService(second, secondProfiles, mail, secondAudit, clock)
                .CreateAsync(id, current.Revision, "new@example.invalid", "contact-test");
            mail.Release.SetResult();
            Assert.Equal(412, (await Assert.ThrowsAsync<ProfileOperationException>(() => sending)).StatusCode);
            Assert.Equal("new@example.invalid", (await secondProfiles.ReadAsync(id)).ContactEmail.Address);
            Assert.Equal(ProfileContactChallengeState.Delivered,
                (await second.ProfileContactChallenges.AsNoTracking().SingleAsync(c => c.Id == Guid.Parse(replacement.ChallengeId))).State);
        }
        finally { mail.Release.TrySetResult(); }
    }
}
