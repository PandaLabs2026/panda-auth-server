using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using PandaAuth.Server.Domain;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Admin;

/// <summary>
/// 管理审计条目构造：actor 取自 Bearer 令牌主体（sub/name），IP 取自连接层
/// （BFF 直连调用时已由 ForwardedHeaders 还原为真实客户端 IP）。
/// internal 以便单元测试直接断言字段映射。
/// </summary>
internal static class AdminAuditing
{
    public static AdminAuditLog Entry(
        ClaimsPrincipal actor,
        string action,
        string targetType,
        string? targetId,
        object? detail,
        string? ipAddress)
        => new()
        {
            ActorUserId = actor.FindFirst(Claims.Subject)?.Value ?? string.Empty,
            ActorUserName = actor.FindFirst(Claims.Name)?.Value,
            Action = action,
            TargetType = targetType,
            TargetId = targetId,
            Detail = detail is null ? null : JsonSerializer.Serialize(detail),
            IpAddress = ipAddress,
        };
}

/// <summary>
/// 服务端生成的一次性随机密码：满足站内策略（长度 ≥10，含大写/小写/数字/非字母数字）。
/// 使用 RandomNumberGenerator（CSPRNG）而非 Random。
/// </summary>
internal static class AdminPasswordGenerator
{
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!@#$%^&*-_=+";
    private const string All = Upper + Lower + Digits + Symbols;

    public static string Generate(int length = 16)
    {
        // 每类至少一个，其余从全池抽取，最后洗牌（避免前四位固定类别被猜结构）。
        // 字符池刻意去掉易混淆字符（I/l/1/O/0）。
        var chars = new char[length];
        chars[0] = Pick(Upper);
        chars[1] = Pick(Lower);
        chars[2] = Pick(Digits);
        chars[3] = Pick(Symbols);
        for (var i = 4; i < length; i++)
        {
            chars[i] = Pick(All);
        }

        Shuffle(chars);
        return new string(chars);
    }

    private static char Pick(string pool)
        => pool[RandomNumberGenerator.GetInt32(pool.Length)];

    private static void Shuffle(char[] array)
    {
        for (var i = array.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (array[i], array[j]) = (array[j], array[i]);
        }
    }
}

/// <summary>
/// 客户端权限的服务端 allowlist：目录（供 UI 复选组）与写入校验共用同一份事实源。
/// 刻意只开放 server 已启用的能力（如响应类型只放 code）——写入校验拒绝一切未知形态，
/// OpenIddict 权限串是协议级行为开关，拼错的字符串不会报错、只会静默失效。
/// </summary>
internal static class PermissionCatalog
{
    public static readonly AdminOptionGroup[] Groups =
    [
        new("端点",
        [
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Revocation,
            Permissions.Endpoints.Introspection,
        ]),
        new("授权类型",
        [
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.ClientCredentials,
            Permissions.GrantTypes.RefreshToken,
        ]),
        new("响应类型",
        [
            Permissions.ResponseTypes.Code,
        ]),
        new("Scope",
        [
            Permissions.Scopes.Email,
            Permissions.Scopes.Profile,
            Permissions.Scopes.Roles,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess,
            Permissions.Prefixes.Scope + "api",
        ]),
        new("要求",
        [
            Requirements.Features.ProofKeyForCodeExchange,
        ]),
    ];

    private static readonly HashSet<string> Known =
        Groups.SelectMany(group => group.Options).ToHashSet(StringComparer.Ordinal);

    /// <summary>已知权限，或「scp: + 非空且不含空白的后缀」的自定义 scope 授权形态。</summary>
    public static bool IsAllowed(string permission)
        => Known.Contains(permission)
            || (permission.StartsWith(Permissions.Prefixes.Scope, StringComparison.Ordinal)
                && permission.Length > Permissions.Prefixes.Scope.Length
                && !permission.Any(char.IsWhiteSpace));
}
