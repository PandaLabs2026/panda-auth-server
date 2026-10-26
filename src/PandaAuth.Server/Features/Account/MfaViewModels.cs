namespace PandaAuth.Server.Features.Account;

/// <summary>管理员安全验证页模型（Passkey 退役后 TOTP-first，AUTH-DELIVERY-002）。</summary>
public sealed class MfaViewModel { public bool HasTotp { get; init; } public int RetiredPasskeyCount { get; init; } public string ReturnUrl { get; init; } = "/admin/"; }
public sealed record ConfirmTotpRequest { public Guid FactorId { get; init; } public string Code { get; init; } = string.Empty; }
public sealed record ConsumeRecoveryCodeRequest { public string Code { get; init; } = string.Empty; }
public sealed record RevokeMfaFactorRequest { public Guid FactorId { get; init; } }

/// <summary>用户自助域操作授权签发请求（/account/mfa/user/grants）。</summary>
public sealed record UserGrantRequest
{
    public string Operation { get; init; } = string.Empty;
    public string TargetId { get; init; } = string.Empty;
    public Dictionary<string, string?>? Parameters { get; init; }
    public string TotpCode { get; init; } = string.Empty;
    public string? CurrentPassword { get; init; }
}

/// <summary>登录路径 MFA 挑战页模型（LoginMfaChallengeController）。挑战因子 = TOTP / 恢复码。</summary>
public sealed class LoginMfaChallengeViewModel
{
    public string ReturnUrl { get; init; } = "/";
    public bool HasTotp { get; init; }
    public bool HasRecoveryCodes { get; init; }
}

/// <summary>挑战页 TOTP 表单提交。</summary>
public sealed class LoginMfaChallengeTotpRequest
{
    public string Code { get; init; } = string.Empty;
    public string? ReturnUrl { get; init; }
}

/// <summary>挑战页恢复码表单提交（Passkey 退役后的自救通道）。</summary>
public sealed class LoginMfaChallengeRecoveryRequest
{
    public string Code { get; init; } = string.Empty;
    public string? ReturnUrl { get; init; }
}
