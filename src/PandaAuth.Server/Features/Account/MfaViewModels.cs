using Fido2NetLib;

namespace PandaAuth.Server.Features.Account;

public sealed class MfaViewModel { public int ActivePasskeyCount { get; init; } public bool HasTotp { get; init; } public string ReturnUrl { get; init; } = "/admin/"; }
public sealed class CompletePasskeyEnrollmentRequest { public Guid CeremonyId { get; init; } public AuthenticatorAttestationRawResponse? Response { get; init; } public string? FriendlyName { get; init; } }
public sealed class CompletePasskeyAssertionRequest { public Guid CeremonyId { get; init; } public AuthenticatorAssertionRawResponse? Response { get; init; } }
public sealed class ConfirmTotpRequest { public Guid FactorId { get; init; } public string Code { get; init; } = string.Empty; }
