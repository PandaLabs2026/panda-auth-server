using PandaAuth.Server.Features.Profile;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SelfProfileInputTests
{
    [Fact]
    public void Patch_retains_presence_and_normalizes_name_after_scalar_counting()
    {
        var patch = SelfProfileInput.ParsePatch("{\"displayName\":\"  🐼  \",\"biography\":null}");
        Assert.True(patch.HasDisplayName);
        Assert.Equal("🐼", patch.DisplayName);
        Assert.True(patch.HasBiography);
        Assert.Null(patch.Biography);
        Assert.False(SelfProfileInput.ParsePatch("{\"biography\":\"hello\"}").HasDisplayName);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"subject\":\"other\"}")]
    [InlineData("{\"displayName\":null}")]
    [InlineData("{\"biography\":2}")]
    [InlineData("{\"biography\":null,\"biography\":\"override\"}")]
    [InlineData("{\"DisplayName\":\"name\"}")]
    [InlineData("{\"displayName\":\"\\uD800\"}")]
    [InlineData("{\"biography\":\"\\u0000\"}")]
    public void Patch_rejects_ambiguous_and_invalid_inputs(string json)
        => Assert.Throws<ProfileInputException>(() => SelfProfileInput.ParsePatch(json));

    [Fact]
    public void Scalar_limits_allow_astral_characters_without_counting_utf16_units()
    {
        var allowed = string.Concat(Enumerable.Repeat("🐼", 80));
        Assert.Equal(allowed, SelfProfileInput.ParsePatch("{\"displayName\":\"" + allowed + "\"}").DisplayName);
        Assert.Throws<ProfileInputException>(() => SelfProfileInput.ParsePatch("{\"displayName\":\"" + allowed + "x\"}"));
        Assert.Throws<ProfileInputException>(() => SelfProfileInput.ParsePatch("{\"biography\":\"" + new string('x', 1001) + "\"}"));
    }

    [Theory]
    [InlineData(" person+tag@example.invalid ", "person+tag@example.invalid")]
    [InlineData("Mixed.Name@Example.invalid", "Mixed.Name@Example.invalid")]
    public void Contact_address_preserves_identity_independent_syntax(string input, string expected)
        => Assert.Equal(expected, SelfProfileInput.NormalizeContactAddress(input));

    [Theory]
    [InlineData("Name <person@example.invalid>")]
    [InlineData("\r\nperson@example.invalid")]
    [InlineData("not an address")]
    public void Contact_address_rejects_display_names_and_control_characters(string input)
        => Assert.Throws<ProfileInputException>(() => SelfProfileInput.NormalizeContactAddress(input));

    [Theory]
    [InlineData("\"0\"", true)]
    [InlineData("\"0123456789abcdef0123456789abcdef\"", true)]
    [InlineData("*", false)]
    [InlineData("W/\"0\"", false)]
    [InlineData("\"0\",\"1\"", false)]
    [InlineData("0", false)]
    [InlineData("\"0\"\n", false)]
    public void Revision_only_accepts_a_single_canonical_strong_etag(string value, bool expected)
        => Assert.Equal(expected, SelfProfileInput.IsRevision(value));
    [Fact]
    public void Json_body_limit_counts_bytes_and_uses_a_distinct_error()
    {
        var error = Assert.Throws<ProfileInputException>(() => SelfProfileInput.ParsePatch(new string(' ', 16385)));
        Assert.Equal(413, error.StatusCode);
        Assert.Equal("profile_request_too_large", error.Code);
    }
}
