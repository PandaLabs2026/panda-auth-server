using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Authorization;

// This binding is supplied by the server after validating the issuer, tenant and client
// registration. The caller supplies the exact scope/resource context of the initial request.
internal sealed record NativeLoginBinding(
    TenantId TenantId, Uri Issuer, string ClientId, string CodeChallenge, string? Scope,
    ImmutableArray<string> Resources, string? RedirectUri, string? Nonce = null)
{
    internal string StorageKey => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
    {
        Tenant = TenantId.Value,
        Issuer = Issuer.AbsoluteUri,
        ClientId,
        CodeChallenge,
        Scope,
        Resources,
        RedirectUri,
        Nonce,
    })));
}

internal enum NativeLoginStatus
{
    TotpRequired,
    InvalidCredentials,
    InvalidChallenge,
    RateLimited,
    Cancelled,
    Verified,
}

internal sealed record NativeLoginResult(NativeLoginStatus Status, Guid? Challenge = null, PandaUser? User = null);

internal sealed class NativeLoginChallengeService(
    MfaChallengeStore challenges,
    UserService users,
    LoginSessionService sessions,
    LoginRateLimiter limiter,
    IPasswordHasher hasher,
    DummyPasswordHash dummyPassword,
    MfaService mfa,
    LoginAuditWriter loginAudit,
    TimeProvider clock)
{
    private const string Purpose = "native-login-totp";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    internal async Task<NativeLoginResult> StartAsync(
        NativeLoginBinding binding, string username, string password, string? ipAddress, string? userAgent, CancellationToken ct)
    {
        username = username.Trim();
        using var ipLease = limiter.AttemptByIp(ipAddress);
        if (!ipLease.IsAcquired) return new(NativeLoginStatus.RateLimited);
        using var accountLease = limiter.AttemptByAccount(username);
        if (!accountLease.IsAcquired) return new(NativeLoginStatus.RateLimited);

        var account = await users.FindByNameAsync(username);
        var (verified, failure) = await VerifyPasswordAsync(account, password, ct);
        await loginAudit.RecordAsync(new LoginLog
        {
            UserId = account?.Id,
            UserName = username,
            ClientId = binding.ClientId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Succeeded = verified is not null,
            FailureReason = failure,
        }, ct);
        if (verified is null) return new(NativeLoginStatus.InvalidCredentials);

        var pending = new PendingUser(verified.Id, AccountSecurityVersion.From(verified));
        var value = JsonSerializer.SerializeToUtf8Bytes(pending);
        var challenge = await challenges.CreateAsync(Purpose, binding.StorageKey, value, Lifetime, ct);
        return new(NativeLoginStatus.TotpRequired, challenge);
    }

    internal async Task<NativeLoginResult> VerifyTotpAsync(
        NativeLoginBinding binding, Guid handle, string otp, string? ipAddress, CancellationToken ct)
    {
        using var ipLease = limiter.AttemptMfaChallengeByIp(ipAddress);
        if (!ipLease.IsAcquired) return new(NativeLoginStatus.RateLimited);
        var stored = await challenges.ConsumeAsync(handle, Purpose, binding.StorageKey, ct);
        if (stored is null) return new(NativeLoginStatus.InvalidChallenge);

        var pending = JsonSerializer.Deserialize<PendingUser>(stored.Value);
        if (pending is null) return new(NativeLoginStatus.InvalidChallenge);
        using var accountLease = limiter.AttemptMfaChallengeByUser(pending.UserId);
        if (!accountLease.IsAcquired) return new(NativeLoginStatus.RateLimited);
        var current = await users.FindByIdAsync(pending.UserId);
        if (!Matches(current, pending)) return new(NativeLoginStatus.InvalidChallenge);

        if (!await mfa.VerifyAsync(pending.UserId, otp, ct))
        {
            var replacement = await challenges.TryCreateUntilAsync(Purpose, binding.StorageKey, stored.Value, stored.ExpiresAt, ct);
            return replacement is null ? new(NativeLoginStatus.InvalidChallenge) : new(NativeLoginStatus.InvalidCredentials, replacement);
        }

        var reloaded = await users.ReloadAsync(pending.UserId);
        if (stored.ExpiresAt <= clock.GetUtcNow() || !Matches(reloaded, pending))
            return new(NativeLoginStatus.InvalidChallenge);
        return new(NativeLoginStatus.Verified, User: reloaded);
    }

    internal async Task<NativeLoginResult> CancelAsync(
        NativeLoginBinding binding, Guid handle, string? ipAddress, CancellationToken ct)
    {
        using var lease = limiter.AttemptMfaChallengeByIp(ipAddress);
        if (!lease.IsAcquired) return new(NativeLoginStatus.RateLimited);
        var cancelled = await challenges.ConsumeAsync(handle, Purpose, binding.StorageKey, ct);
        return new(cancelled is null ? NativeLoginStatus.InvalidChallenge : NativeLoginStatus.Cancelled);
    }

    private async Task<(PandaUser? User, string? Failure)> VerifyPasswordAsync(PandaUser? account, string password, CancellationToken ct)
    {
        if (account is not { Status: UserStatus.Active })
        {
            await hasher.VerifyAsync(dummyPassword.Value, password, ct);
            return (null, account is null ? "user_not_found" : "account_frozen");
        }

        var passwordResult = await sessions.CheckPasswordSignInAsync(account, password, lockoutOnFailure: true);
        if (!passwordResult.Succeeded && !passwordResult.RequiresMfaReconfiguration)
            return (null, passwordResult.IsLockedOut ? "locked_out" : passwordResult.IsNotAllowed ? "not_allowed" : "wrong_password");
        if (passwordResult.User is not { EmailConfirmed: true, SecurityStamp.Length: > 0 } verified
            || !(await mfa.ListFactorsAsync(verified.Id, ct)).Any(factor => factor.Type == "totp"))
            return (null, "not_allowed");
        return (verified, null);
    }

    private static bool Matches(PandaUser? user, PendingUser pending)
        => user is { Status: UserStatus.Active, EmailConfirmed: true, SecurityStamp.Length: > 0 }
            && string.Equals(AccountSecurityVersion.From(user), pending.SecurityVersion, StringComparison.Ordinal);

    private sealed record PendingUser(string UserId, string SecurityVersion);
}
