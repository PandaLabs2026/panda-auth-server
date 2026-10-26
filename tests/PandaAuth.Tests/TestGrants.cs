using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

/// <summary>
/// 操作授权测试基建：与生产同构的 MfaOperationGrantService（含 Argon2id 哈希器），
/// 以及给受门禁端点测试用的「真实验证授权」签发（真实 TOTP + 操作者密码 → 授权头 + 真实主体）。
/// </summary>
internal static class TestGrants
{
    internal static readonly byte[] TotpKey = Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    private static readonly ConcurrentDictionary<IServiceProvider, GrantActor> Actors = new();

    internal static MfaOperationGrantService Create(IServiceProvider provider, TimeProvider? clock = null)
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var time = clock ?? TimeProvider.System;
        return new MfaOperationGrantService(
            new MfaChallengeStore(db, time),
            new TotpFactorService(db, new TotpSecretProtector(TotpKey, "v1"), time),
            db,
            provider.GetRequiredService<UserService>(),
            provider.GetRequiredService<IPasswordHasher>(),
            time);
    }

    /// <summary>
    /// 给受门禁端点的控制器测试签发真实操作授权并装进请求头：真实管理员（已绑 TOTP、密码已知）
    /// → TOTP 验证 + 密码核验 → 授权行 → X-Panda-Mfa-Grant 头 + 真实 Bearer 主体。
    /// 连续多次授权按需轮换 TOTP 因子（重置 LastAcceptedTimeStep），同一时间步可继续签发。
    /// </summary>
    internal static async Task AuthorizeAsync(
        IServiceProvider provider, Controller controller, string operation, string targetId,
        IReadOnlyDictionary<string, string?>? parameters, string? actorId = null,
        bool replacePrincipal = true, string password = "Strong!Pass123")
    {
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        PandaUser effectiveActor;
        if (actorId is null)
        {
            var actor = Actors.GetOrAdd(provider, static _ => new GrantActor());
            if (actor.User is null)
            {
                var users = provider.GetRequiredService<UserService>();
                var roles = provider.GetRequiredService<RoleService>();
                if (!await roles.RoleExistsAsync(PandaUser.AdminRole))
                    await roles.CreateAsync(new PandaRole { Name = PandaUser.AdminRole });
                var user = new PandaUser { UserName = $"grant-actor-{Guid.NewGuid():N}", EmailConfirmed = true };
                await users.CreateAsync(user, password);
                await users.AddToRoleAsync(user, PandaUser.AdminRole);
                actor.User = user;
            }
            effectiveActor = actor.User;
        }
        else
        {
            // 自操作测试：授权与请求主体同属指定用户（该用户密码由调用方给出）。
            effectiveActor = await provider.GetRequiredService<UserService>().FindByIdAsync(actorId)
                ?? throw new InvalidOperationException($"actor {actorId} not seeded");
        }

        // 每次签发前重建 TOTP 因子：既保证已确认状态，也清掉 LastAcceptedTimeStep，
        // 使同一 30 秒时间步内可以连续签发多张授权（多操作测试）。
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        var factorId = Guid.NewGuid();
        foreach (var stale in db.TotpFactors.Where(x => x.UserId == effectiveActor.Id).ToList()) stale.RevokedAt = DateTimeOffset.UtcNow;
        var protectedSecret = new TotpSecretProtector(TotpKey, "v1").Protect(effectiveActor.Id, factorId, secret);
        db.TotpFactors.Add(new MfaTotpFactor
        {
            Id = factorId,
            UserId = effectiveActor.Id,
            ConfirmedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            KeyVersion = protectedSecret.KeyVersion,
            Nonce = protectedSecret.Nonce,
            Ciphertext = protectedSecret.Ciphertext,
            Tag = protectedSecret.Tag,
        });
        await db.SaveChangesAsync();

        var grants = Create(provider);
        var (issued, error) = await grants.IssueAsync(effectiveActor.Id, operation, targetId, parameters,
            TotpCode(secret), password, CancellationToken.None);
        Assert.True(issued is not null, $"grant issuance failed: {error}");

        var context = controller.HttpContext ?? new DefaultHttpContext { RequestServices = provider };
        context.Request.Headers[MfaOperationGrantGate.GrantHeader] = issued!.GrantId.ToString();
        if (replacePrincipal)
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(Claims.Subject, effectiveActor.Id),
                new Claim(Claims.Name, effectiveActor.UserName ?? "grant-actor"),
                new Claim(Claims.Role, PandaAuthRoles.Admin),
                new Claim(MfaClaimTypes.Method, MfaClaimTypes.Totp),
                new Claim(MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            ], "TestBearer", Claims.Name, Claims.Role));
        }
    }

    // ---- 授权参数构造器：与控制器消费侧的规范化口径一致（排序拼接）。 ----

    internal static Dictionary<string, string?> Roles(params string[] roles)
        => new() { ["roles"] = string.Join(",", roles.Order(StringComparer.Ordinal)) };

    internal static Dictionary<string, string?> Status(PandaAuth.Shared.UserStatus status)
        => new() { ["status"] = status.ToString() };

    internal static Dictionary<string, string?> ConfirmUserName(string userName)
        => new() { ["confirmUserName"] = userName };

    internal static Dictionary<string, string?> Uris(IReadOnlyList<string> redirectUris, IReadOnlyList<string>? postLogoutUris = null)
        => new()
        {
            ["redirectUris"] = string.Join("\n", redirectUris.Order(StringComparer.Ordinal)),
            ["postLogoutUris"] = postLogoutUris is null ? null : string.Join("\n", postLogoutUris.Order(StringComparer.Ordinal)),
        };

    internal static Dictionary<string, string?> Permissions(IReadOnlyList<string> permissions)
        => new() { ["permissions"] = string.Join("\n", permissions.Order(StringComparer.Ordinal)) };

    internal static Dictionary<string, string?> Claim(string claimType, string claimValue, string scope)
        => new() { ["claimType"] = claimType, ["claimValue"] = claimValue, ["scope"] = scope };

    internal static Dictionary<string, string?> ClaimId(long claimId)
        => new() { ["claimId"] = claimId.ToString() };

    /// <summary>构造已携带真实登录 cookie 的请求上下文（MarkMfaAsync 需要可认证会话）。</summary>
    internal static async Task<(DefaultHttpContext Context, ClaimsPrincipal Principal)> SignedInContextAsync(
        ServiceProvider provider, PandaUser user, string? mfaMethod = null)
    {
        using var issueScope = provider.CreateScope();
        var issue = new DefaultHttpContext { RequestServices = issueScope.ServiceProvider };
        issue.Request.Scheme = "https";
        issue.Request.Host = new HostString("localhost");
        var sessions = issueScope.ServiceProvider.GetRequiredService<LoginSessionService>();
        if (mfaMethod is null) await sessions.SignInAsync(issue, user, false);
        else await sessions.SignInWithMfaAsync(issue, user, mfaMethod);

        var cookie = issue.Response.Headers.SetCookie.Single()!.Split(';')[0];
        using var verificationScope = provider.CreateScope();
        var context = new DefaultHttpContext { RequestServices = verificationScope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = cookie;
        var ticket = await context.AuthenticateAsync(LoginSessionService.Scheme);
        if (!ticket.Succeeded) throw new InvalidOperationException("Test login cookie did not authenticate.");
        context.User = ticket.Principal!;
        return (context, ticket.Principal!);
    }

    /// <summary>标准 RFC 6238（SHA1/30s/6 位）生成当前验证码——独立于生产 TotpVerifier 实现，互为印证。</summary>
    internal static string TotpCode(byte[] secret)
    {
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> counter = stackalloc byte[8];
        for (var index = counter.Length - 1; index >= 0; index--)
        {
            counter[index] = (byte)step;
            step >>= 8;
        }
        using var hmac = new System.Security.Cryptography.HMACSHA1(secret);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) |
                     (hash[offset + 1] << 16) |
                     (hash[offset + 2] << 8) |
                     hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private sealed class GrantActor
    {
        public PandaUser? User { get; set; }
    }
}
