namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public static class MfaClaimTypes
{
    public const string Method = "amr";
    public const string VerifiedAt = "panda_mfa_at";
    public const string WebAuthn = "webauthn";
    public const string Totp = "totp";
    public const string RecoveryCode = "recovery_code";
}
