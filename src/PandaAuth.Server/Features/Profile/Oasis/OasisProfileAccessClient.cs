using System.Data.Common;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile.Oasis;

// Concrete consumer of the immutable Oasis #150 contract. No profile values or publication consent.
internal sealed class OasisProfileAccessClient(OasisProfileOptions options, IAuthorizationService authorization,
    PandaAuthDbContext db, IHttpClientFactory clients, SecurityEventWriter audit)
{
    internal const string Route = "/api/integrations/panda-auth/v1/profile-access";
    internal const string Audience = "oasis-profile-access-api";
    internal const string Scope = "profile.membership.resolve";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public async Task<OasisMembershipProof?> ResolveAsync(HttpContext caller, Guid organizationKey,
        Guid memberKey, IReadOnlyList<string> fields, CancellationToken cancellationToken = default)
    {
        if (!options.Enabled) return null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, caller.RequestAborted);
        cancellation.Token.ThrowIfCancellationRequested();
        var selected = fields.ToArray();
        if (!options.OrganizationKeys.Contains(organizationKey) || memberKey == Guid.Empty
            || selected.Length is < 1 or > 4 || selected.Any(f => !IsField(f))
            || selected.Distinct(StringComparer.Ordinal).Count() != selected.Length) return null;
        var actor = ProfileAccess.ActorId(caller.User);
        var issuers = caller.User.GetClaims(OpenIddictConstants.Claims.Issuer);
        var types = caller.User.GetClaims(PandaAuthClaims.SubjectType);
        if (actor is null || string.IsNullOrWhiteSpace(actor) || issuers.Length != 1 || issuers[0] != options.Issuer
            || types.Length != 1 || types[0] != PandaAuthClaims.SubjectTypes.Human) return null;
        try
        {
            if (!(await authorization.AuthorizeAsync(caller.User, caller, ProfileAccess.ReadPolicy)).Succeeded) return null;
            // One deadline covers both outbound operations and bounded reads. No authorization/token cache.
            cancellation.CancelAfter(TimeSpan.FromSeconds(3));
            var ct = cancellation.Token;
            using var client = clients.CreateClient("oasis-profile-access");
            var token = await TokenAsync(client, ct);
            if (token is null) return await FinishAsync(null);
            var requestId = Guid.NewGuid();
            var payload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                requestId, organizationKey, requester = new { issuer = options.Issuer, subject = actor },
                targetMemberKey = memberKey, requestedFields = selected,
            });
            if (payload.Length > 16384) return await FinishAsync(null);
            using var request = new HttpRequestMessage(HttpMethod.Post, options.Endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Content = new ByteArrayContent(payload);
            request.Content.Headers.ContentType = new("application/json") { CharSet = "utf-8" };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            using var json = await ReadJsonAsync(response, 8192, ct);
            ct.ThrowIfCancellationRequested();
            if (json is null) return await FinishAsync(null);
            var root = json.RootElement;
            if (!Shape(root, "requestId", "organizationKey", "targetMemberKey", "target", "allowedFields")
                || !BoundGuid(root, "requestId", requestId) || !BoundGuid(root, "organizationKey", organizationKey)
                || !BoundGuid(root, "targetMemberKey", memberKey)) return await FinishAsync(null);
            var target = root.GetProperty("target");
            if (!Shape(target, "issuer", "subject") || Text(target, "issuer") != options.Issuer) return await FinishAsync(null);
            var targetId = Text(target, "subject");
            var allowed = root.GetProperty("allowedFields");
            if (string.IsNullOrWhiteSpace(targetId) || targetId.Length > 450 || allowed.ValueKind != JsonValueKind.Array
                || allowed.GetArrayLength() is < 1 or > 4) return await FinishAsync(null);
            var result = new List<string>();
            foreach (var field in allowed.EnumerateArray())
            {
                if (field.ValueKind != JsonValueKind.String || field.GetString() is not { } name
                    || !IsField(name) || !selected.Contains(name, StringComparer.Ordinal) || result.Contains(name))
                    return await FinishAsync(null);
                result.Add(name);
            }
            if (!await db.Users.AsNoTracking().AnyAsync(u => u.Id == targetId && u.Status == UserStatus.Active, ct))
                return await FinishAsync(null);
            ct.ThrowIfCancellationRequested();
            return await FinishAsync(new(organizationKey, memberKey, actor, targetId, result.AsReadOnly()));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && !caller.RequestAborted.IsCancellationRequested)
        {
            return await FinishAsync(null);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or ArgumentException
            or DbException or DbUpdateException)
        {
            return await FinishAsync(null);
        }

        async Task<OasisMembershipProof?> FinishAsync(OasisMembershipProof? proof)
        {
            // No response bodies, URLs, credential material, values, or untrusted target references in audit.
            await audit.RecordAsync(new SecurityEventEntry("profile.membership.resolve", actor, actor,
                "profile", proof?.TargetId, null, new { fields = selected, outcome = proof is null ? "unavailable" : "allowed" },
                null, null, caller.TraceIdentifier), cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            caller.RequestAborted.ThrowIfCancellationRequested();
            return proof;
        }
    }

    private async Task<string?> TokenAsync(HttpClient client, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            new Uri(new Uri(options.Issuer), PandaAuthEndpoints.Token));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = OpenIddictConstants.GrantTypes.ClientCredentials,
            ["client_id"] = options.ClientId, ["client_secret"] = options.ClientSecret!, ["scope"] = Scope,
            ["resource"] = Audience,
        });
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        using var json = await ReadJsonAsync(response, 16384, ct);
        if (json is null) return null;
        var root = json.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return null;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!names.Add(property.Name) || property.Name is not ("access_token" or "token_type" or "expires_in" or "scope")) return null;
        var token = Text(root, "access_token");
        if (!string.Equals(Text(root, "token_type"), "Bearer", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrEmpty(token) || token.Length > 12288 || token.Any(c => c <= 32 || c >= 127)
            || !root.TryGetProperty("expires_in", out var expires) || expires.ValueKind != JsonValueKind.Number
            || !expires.TryGetInt64(out var seconds) || seconds <= 0
            || (root.TryGetProperty("scope", out _) && Text(root, "scope") != Scope)) return null;
        return token;
    }

    private static async Task<JsonDocument?> ReadJsonAsync(HttpResponseMessage response, int maximum, CancellationToken ct)
    {
        var type = response.Content.Headers.ContentType;
        if (response.StatusCode != System.Net.HttpStatusCode.OK || response.Headers.CacheControl?.NoStore != true
            || response.Content.Headers.ContentEncoding.Count != 0 || response.Content.Headers.ContentLength > maximum
            || !string.Equals(type?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
            || (type?.CharSet is { } charset && !string.Equals(charset.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase))) return null;
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var bytes = new MemoryStream();
        var buffer = new byte[1024];
        while (true)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, maximum + 1 - (int)bytes.Length)), ct);
            if (count == 0) break;
            bytes.Write(buffer, 0, count);
            if (bytes.Length > maximum) return null;
        }
        ct.ThrowIfCancellationRequested();
        return JsonDocument.Parse(Utf8.GetString(bytes.GetBuffer(), 0, (int)bytes.Length), new() { MaxDepth = 4 });
    }

    private static bool Shape(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object) return false;
        var actual = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !actual.Add(property.Name)) return false;
        return actual.Count == expected.Length;
    }
    private static string? Text(JsonElement element, string name) => element.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static bool BoundGuid(JsonElement element, string name, Guid expected)
        => Text(element, name) is { Length: 36 } text && Guid.TryParseExact(text, "D", out var actual) && actual == expected;
    private static bool IsField(string value) => value is "displayName" or "avatar" or "biography" or "contactEmail";
}
