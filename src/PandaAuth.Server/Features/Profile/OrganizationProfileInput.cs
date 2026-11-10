using System.Text;
using System.Text.Json;
using PandaAuth.Shared;

namespace PandaAuth.Server.Features.Profile;

internal static class OrganizationProfileInput
{
    // Ordering also defines the persisted four-bit selection mask.
    private static readonly string[] Names = [ProfileFields.DisplayName, ProfileFields.Avatar,
        ProfileFields.Biography, ProfileFields.ContactEmail];

    internal static string[] ParseSelection(string json)
    {
        if (Encoding.UTF8.GetByteCount(json) > SelfProfileInput.MaxJsonBytes)
            throw new ProfileInputException("profile_request_too_large", 413);
        try
        {
            using var document = JsonDocument.Parse(json, new() { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw Invalid();
            var properties = document.RootElement.EnumerateObject().ToArray();
            if (properties.Length != 1 || properties[0].Name != "fields"
                || properties[0].Value.ValueKind != JsonValueKind.Array) throw Invalid();
            var array = properties[0].Value;
            if (array.GetArrayLength() > Names.Length) throw Invalid();
            var result = new List<string>();
            foreach (var item in array.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String || item.GetString() is not { } name
                    || !Names.Contains(name, StringComparer.Ordinal) || result.Contains(name, StringComparer.Ordinal)) throw Invalid();
                result.Add(name);
            }
            return result.ToArray();
        }
        catch (JsonException) { throw Invalid(); }
        catch (InvalidOperationException) { throw Invalid(); }
    }

    internal static string[] ParseRequestedFields(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128) throw Invalid();
        var fields = value.Split(',');
        if (fields.Length is < 1 or > 4 || fields.Any(f => !Names.Contains(f, StringComparer.Ordinal))
            || fields.Distinct(StringComparer.Ordinal).Count() != fields.Length) throw Invalid();
        return fields;
    }

    internal static int Mask(IEnumerable<string> validatedFields)
        => validatedFields.Aggregate(0, (mask, name) => mask | (1 << Array.IndexOf(Names, name)));

    internal static string[] Fields(int mask) => Names.Where((_, index) => (mask & (1 << index)) != 0).ToArray();

    internal static OrganizationProfileDto? Project(SelfProfileDto profile, IReadOnlyList<string> selected,
        IReadOnlyList<string> allowed, IReadOnlyList<string> requested)
    {
        var visible = selected.Intersect(allowed, StringComparer.Ordinal).Intersect(requested, StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
        if (profile.ContactEmail.State != ProfileContactEmailState.Verified || profile.ContactEmail.Address is null)
            visible.Remove(ProfileFields.ContactEmail);
        if (profile.DisplayName is null) visible.Remove(ProfileFields.DisplayName);
        if (profile.Biography is null) visible.Remove(ProfileFields.Biography);
        if (visible.Count == 0) return null;
        return new(
            visible.Contains(ProfileFields.DisplayName) ? profile.DisplayName : null,
            visible.Contains(ProfileFields.Biography) ? profile.Biography : null,
            visible.Contains(ProfileFields.Avatar) ? profile.HasAvatar : null,
            visible.Contains(ProfileFields.ContactEmail) ? profile.ContactEmail.Address : null);
    }

    private static ProfileInputException Invalid() => new("profile_request_invalid", 400);
}
