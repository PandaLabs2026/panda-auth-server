using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

/// <summary>
/// Builds WebAuthn ceremonies from the authoritative credential store. The browser receives
/// public options only; original options remain server-side and can be consumed once.
/// </summary>
public sealed class WebAuthnCeremonyService(IFido2 fido2, PandaAuthDbContext db, MfaChallengeStore challenges)
{
    public const string EnrollmentPurpose = "webauthn-enrollment";
    public const string AssertionPurpose = "webauthn-assertion";

    public async Task<WebAuthnCeremony<CredentialCreateOptions>> BeginEnrollmentAsync(
        PandaUser user,
        CancellationToken cancellationToken)
    {
        var credentials = await ActiveCredentialsAsync(user.Id, cancellationToken);
        var options = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = Encoding.UTF8.GetBytes(user.Id),
                Name = user.UserName ?? user.Id,
                DisplayName = user.UserName ?? user.Id,
            },
            ExcludeCredentials = credentials.Select(Descriptor).ToArray(),
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.Platform,
                UserVerification = UserVerificationRequirement.Required,
            },
            AttestationPreference = AttestationConveyancePreference.None,
        });
        return await StoreAsync(EnrollmentPurpose, user.Id, options.ToJson(), options, cancellationToken);
    }

    public async Task<WebAuthnCeremony<AssertionOptions>> BeginAssertionAsync(
        PandaUser user,
        CancellationToken cancellationToken)
    {
        var credentials = await ActiveCredentialsAsync(user.Id, cancellationToken);
        if (credentials.Count == 0)
        {
            throw new InvalidOperationException("此账号尚未配置可用的 Passkey。");
        }

        var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = credentials.Select(Descriptor).ToArray(),
            UserVerification = UserVerificationRequirement.Required,
        });
        return await StoreAsync(AssertionPurpose, user.Id, options.ToJson(), options, cancellationToken);
    }

    public async Task<MfaWebAuthnCredential> CompleteEnrollmentAsync(
        PandaUser user,
        Guid ceremonyId,
        AuthenticatorAttestationRawResponse response,
        string? friendlyName,
        CancellationToken cancellationToken)
    {
        var challenge = await challenges.ConsumeAsync(ceremonyId, EnrollmentPurpose, user.Id, cancellationToken);
        if (challenge is null)
        {
            throw new InvalidOperationException("Passkey 注册请求已过期或已使用。");
        }

        var options = CredentialCreateOptions.FromJson(Encoding.UTF8.GetString(challenge.Value));
        var result = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = async (args, ct) => !(await db.WebAuthnCredentials
                .Select(credential => credential.CredentialId)
                .ToListAsync(ct)).Any(credentialId => credentialId.SequenceEqual(args.CredentialId)),
        }, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var credential = new MfaWebAuthnCredential
        {
            UserId = user.Id,
            CredentialId = result.Id,
            PublicKeyCose = result.PublicKey,
            SignatureCounter = result.SignCount,
            Aaguid = result.AaGuid.ToString(),
            TransportsJson = result.Transports is null ? null : System.Text.Json.JsonSerializer.Serialize(result.Transports),
            BackupEligible = result.IsBackupEligible,
            BackupState = result.IsBackedUp,
            FriendlyName = string.IsNullOrWhiteSpace(friendlyName) ? null : friendlyName.Trim()[..Math.Min(80, friendlyName.Trim().Length)],
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.WebAuthnCredentials.Add(credential);
        await db.SaveChangesAsync(cancellationToken);
        return credential;
    }

    public async Task CompleteAssertionAsync(
        PandaUser user,
        Guid ceremonyId,
        AuthenticatorAssertionRawResponse response,
        CancellationToken cancellationToken)
    {
        var challenge = await challenges.ConsumeAsync(ceremonyId, AssertionPurpose, user.Id, cancellationToken);
        if (challenge is null)
        {
            throw new InvalidOperationException("Passkey 验证请求已过期或已使用。");
        }

        var credential = (await ActiveCredentialsAsync(user.Id, cancellationToken))
            .SingleOrDefault(item => item.CredentialId.SequenceEqual(response.RawId));
        if (credential is null)
        {
            throw new InvalidOperationException("未知或已撤销的 Passkey。");
        }

        var options = AssertionOptions.FromJson(Encoding.UTF8.GetString(challenge.Value));
        var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = credential.PublicKeyCose,
            StoredSignatureCounter = credential.SignatureCounter,
            IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(
                args.CredentialId.SequenceEqual(credential.CredentialId) &&
                args.UserHandle.SequenceEqual(Encoding.UTF8.GetBytes(user.Id))),
        }, cancellationToken);
        credential.SignatureCounter = result.SignCount;
        credential.LastUsedAt = credential.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task<WebAuthnCeremony<TOptions>> StoreAsync<TOptions>(
        string purpose,
        string userId,
        string optionsJson,
        TOptions options,
        CancellationToken cancellationToken)
    {
        var ceremonyId = await challenges.CreateAsync(
            purpose, userId, Encoding.UTF8.GetBytes(optionsJson), TimeSpan.FromMinutes(5), cancellationToken);
        return new WebAuthnCeremony<TOptions>(ceremonyId, options);
    }

    private Task<List<MfaWebAuthnCredential>> ActiveCredentialsAsync(string userId, CancellationToken cancellationToken) =>
        db.WebAuthnCredentials
            .Where(credential => credential.UserId == userId && credential.RevokedAt == null)
            .OrderBy(credential => credential.CreatedAt)
            .ToListAsync(cancellationToken);

    private static PublicKeyCredentialDescriptor Descriptor(MfaWebAuthnCredential credential) =>
        new(credential.CredentialId);
}

public sealed record WebAuthnCeremony<TOptions>(Guid Id, TOptions Options);
