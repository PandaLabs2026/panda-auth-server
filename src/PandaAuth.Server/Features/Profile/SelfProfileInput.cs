using System.Buffers;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PandaAuth.Server.Features.Profile;

public sealed class ProfileInputException(string code, int statusCode) : Exception(code)
{
    public string Code { get; } = code;
    public int StatusCode { get; } = statusCode;
}

public sealed record ProfileTextPatch(bool HasDisplayName, string? DisplayName, bool HasBiography, string? Biography);

/// <summary>Validation at the profile API input boundary; no account lookup or credential normalization.</summary>
public static partial class SelfProfileInput
{
    public const int MaxJsonBytes = 16 * 1024;

    public static ProfileTextPatch ParsePatch(string json)
    {
        if (Encoding.UTF8.GetByteCount(json) > MaxJsonBytes)
            throw new ProfileInputException("profile_request_too_large", 413);
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw InvalidRequest();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            string? displayName = null, biography = null;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!seen.Add(property.Name)) throw InvalidRequest();
                switch (property.Name)
                {
                    case "displayName":
                        if (property.Value.ValueKind != JsonValueKind.String) throw InvalidRequest();
                        displayName = property.Value.GetString()!.Trim();
                        ValidateScalars(displayName, 1, 80);
                        break;
                    case "biography":
                        if (property.Value.ValueKind == JsonValueKind.Null) break;
                        if (property.Value.ValueKind != JsonValueKind.String) throw InvalidRequest();
                        biography = property.Value.GetString();
                        ValidateScalars(biography!, 0, 1000);
                        break;
                    default: throw InvalidRequest();
                }
            }
            if (seen.Count == 0) throw InvalidRequest();
            return new(seen.Contains("displayName"), displayName, seen.Contains("biography"), biography);
        }
        catch (JsonException) { throw InvalidRequest(); }
        catch (InvalidOperationException) { throw InvalidRequest(); }
    }

    public static string NormalizeContactAddress(string address)
    {
        if (address.Any(char.IsControl)) throw InvalidValue();
        address = address.Trim();
        if (address.Length is < 1 or > 256 || !MailAddress.TryCreate(address, out var parsed)
            || !string.Equals(parsed.Address, address, StringComparison.Ordinal)) throw InvalidValue();
        return address;
    }

    public static bool IsRevision(string value) => RevisionPattern().IsMatch(value);

    private static void ValidateScalars(string value, int min, int max)
    {
        var remaining = value.AsSpan();
        var count = 0;
        while (!remaining.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(remaining, out _, out var consumed) != OperationStatus.Done || ++count > max)
                throw InvalidValue();
            remaining = remaining[consumed..];
        }
        if (count < min) throw InvalidValue();
    }

    private static ProfileInputException InvalidRequest() => new("profile_request_invalid", 400);
    private static ProfileInputException InvalidValue() => new("profile_value_invalid", 422);

    [GeneratedRegex(@"\A""(0|[a-f0-9]{32})""\z", RegexOptions.CultureInvariant)]
    private static partial Regex RevisionPattern();
}
