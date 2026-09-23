using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class WebAuthnCeremonyServiceTests
{
    [Fact]
    public async Task BeginEnrollment_RequiresUserVerification_AndExcludesActiveCredentials()
    {
        var fido2 = new CapturingFido2();
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);
        var user = new PandaUser { Id = "admin-1", UserName = "admin@example.test" };
        db.WebAuthnCredentials.AddRange(
            new MfaWebAuthnCredential { UserId = user.Id, CredentialId = [1, 2, 3] },
            new MfaWebAuthnCredential { UserId = user.Id, CredentialId = [4, 5, 6], RevokedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        var service = new WebAuthnCeremonyService(fido2, db, new MfaChallengeStore(db, TimeProvider.System));

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.BeginEnrollmentAsync(user, CancellationToken.None));

        Assert.NotNull(fido2.EnrollmentRequest);
        var request = fido2.EnrollmentRequest!;
        Assert.Equal(UserVerificationRequirement.Required, request.AuthenticatorSelection.UserVerification);
        Assert.Equal(AuthenticatorAttachment.Platform, request.AuthenticatorSelection.AuthenticatorAttachment);
        var credential = Assert.Single(request.ExcludeCredentials);
        Assert.Equal([1, 2, 3], credential.Id);
    }

    [Fact]
    public async Task BeginAssertion_RequiresUserVerification_AndOnlyAllowsActiveCredentials()
    {
        var fido2 = new CapturingFido2();
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N")).Options);
        var user = new PandaUser { Id = "admin-1", UserName = "admin@example.test" };
        db.WebAuthnCredentials.AddRange(
            new MfaWebAuthnCredential { UserId = user.Id, CredentialId = [1, 2, 3] },
            new MfaWebAuthnCredential { UserId = user.Id, CredentialId = [4, 5, 6], RevokedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        var service = new WebAuthnCeremonyService(fido2, db, new MfaChallengeStore(db, TimeProvider.System));

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.BeginAssertionAsync(user, CancellationToken.None));

        Assert.NotNull(fido2.AssertionRequest);
        var request = fido2.AssertionRequest!;
        Assert.Equal(UserVerificationRequirement.Required, request.UserVerification);
        var credential = Assert.Single(request.AllowedCredentials);
        Assert.Equal([1, 2, 3], credential.Id);
    }

    private sealed class CapturingFido2 : IFido2
    {
        public RequestNewCredentialParams? EnrollmentRequest { get; private set; }
        public GetAssertionOptionsParams? AssertionRequest { get; private set; }

        public CredentialCreateOptions RequestNewCredential(RequestNewCredentialParams request)
        {
            EnrollmentRequest = request;
            throw new InvalidOperationException("Stop after capturing the security parameters.");
        }

        public AssertionOptions GetAssertionOptions(GetAssertionOptionsParams request)
        {
            AssertionRequest = request;
            throw new InvalidOperationException("Stop after capturing the security parameters.");
        }

        public Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
