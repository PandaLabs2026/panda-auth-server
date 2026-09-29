using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public sealed record LoginMfaChallenge(string UserId, string SecurityStamp, DateTimeOffset IssuedAt);

/// <summary>
/// 登录路径 MFA 挑战的 pending 状态：密码验证通过但尚未完成第二因子时签发的自包含受保护 cookie。
/// 不携带任何已认证身份——IDP 登录 cookie 只在断言成功后才签发；断言端点只认本 cookie 定位用户，
/// 绝不接受请求体指定 subject。绑定签发时的安全戳：挑战窗口内密码被重置/因子被治理即失效（fail-closed）。
/// 短 TTL + 成功即清除 + 新登录覆盖，防重放不依赖数据库状态。
/// </summary>
public sealed class LoginMfaChallengeService(IDataProtectionProvider protection, TimeProvider clock)
{
    public const string CookieName = "PandaAuth.LoginMfaChallenge.v1";

    /// <summary>挑战有效期：窗口内未完成断言即回到登录页重新认证。</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private static readonly JsonSerializerOptions PayloadOptions = new(JsonSerializerDefaults.General);

    private readonly IDataProtector _protector =
        protection.CreateProtector("PandaAuth.LoginMfaChallenge.v1");

    public void Issue(HttpContext context, string userId, string securityStamp)
    {
        var payload = _protector.Protect(JsonSerializer.Serialize(
            new LoginMfaChallenge(userId, securityStamp, clock.GetUtcNow()), PayloadOptions));
        context.Response.Cookies.Append(CookieName, payload, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            MaxAge = Lifetime,
            Expires = clock.GetUtcNow().Add(Lifetime),
            Path = "/account",
            IsEssential = true,
        });
    }

    /// <summary>读取并校验 pending 挑战；cookie 缺失、无法解保护或超期均返回 null（fail-closed）。</summary>
    public LoginMfaChallenge? Read(HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName, out var payload) || string.IsNullOrEmpty(payload))
            return null;
        LoginMfaChallenge? challenge;
        try
        {
            challenge = JsonSerializer.Deserialize<LoginMfaChallenge>(_protector.Unprotect(payload), PayloadOptions);
        }
        catch (Exception exception) when (
            exception is System.Security.Cryptography.CryptographicException or JsonException)
        {
            return null;
        }
        if (challenge is null ||
            !Guid.TryParse(challenge.UserId, out _) ||
            string.IsNullOrEmpty(challenge.SecurityStamp) ||
            clock.GetUtcNow() - challenge.IssuedAt > Lifetime)
        {
            return null;
        }
        return challenge;
    }

    public void Clear(HttpContext context) => context.Response.Cookies.Delete(CookieName, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Secure = context.Request.IsHttps,
        Path = "/account",
    });
}
