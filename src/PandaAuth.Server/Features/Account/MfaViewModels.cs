using Fido2NetLib;

namespace PandaAuth.Server.Features.Account;

public sealed class MfaViewModel { public int ActivePasskeyCount { get; init; } public bool HasTotp { get; init; } public string ReturnUrl { get; init; } = "/admin/"; }
public sealed class CompletePasskeyEnrollmentRequest { public Guid CeremonyId { get; init; } public AuthenticatorAttestationRawResponse? Response { get; init; } public string? FriendlyName { get; init; } }
public sealed class CompletePasskeyAssertionRequest { public Guid CeremonyId { get; init; } public AuthenticatorAssertionRawResponse? Response { get; init; } }
public sealed class ConfirmTotpRequest { public Guid FactorId { get; init; } public string Code { get; init; } = string.Empty; }
public sealed class ConsumeRecoveryCodeRequest { public string Code { get; init; } = string.Empty; }
public sealed class RevokeMfaFactorRequest { public Guid FactorId { get; init; } }

/// <summary>登录路径 MFA 挑战页模型（LoginMfaChallengeController）。</summary>
public sealed class LoginMfaChallengeViewModel
{
    public string ReturnUrl { get; init; } = "/";
    public bool HasTotp { get; init; }
    public bool HasPasskey { get; init; }
}

/// <summary>挑战页 TOTP 表单提交。</summary>
public sealed class LoginMfaChallengeTotpRequest
{
    public string Code { get; init; } = string.Empty;
    public string? ReturnUrl { get; init; }
}
