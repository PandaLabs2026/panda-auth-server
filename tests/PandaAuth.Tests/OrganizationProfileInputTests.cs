using System.Text.Json;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class OrganizationProfileInputTests
{
    [Theory]
    [InlineData("{\"fields\":[]}")]
    [InlineData("{\"fields\":[\"avatar\",\"biography\"]}")]
    public void Selection_accepts_explicit_revocation_and_known_fields(string json)
        => Assert.NotNull(OrganizationProfileInput.ParseSelection(json));

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("{\"fields\":null}")]
    [InlineData("{\"fields\":[1]}")]
    [InlineData("{\"fields\":[\"roles\"]}")]
    [InlineData("{\"fields\":[\"avatar\",\"avatar\"]}")]
    [InlineData("{\"fields\":[],\"fields\":[\"avatar\"]}")]
    [InlineData("{\"fields\":[],\"subject\":\"other\"}")]
    [InlineData("{\"fields\":[\"\\uD800\"]}")]
    public void Selection_rejects_ambiguous_or_untrusted_input(string json)
        => Assert.Throws<ProfileInputException>(() => OrganizationProfileInput.ParseSelection(json));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("avatar,avatar")]
    [InlineData("roles")]
    [InlineData("avatar, biography")]
    public void Read_requires_a_nonempty_unambiguous_field_set(string? fields)
        => Assert.Throws<ProfileInputException>(() => OrganizationProfileInput.ParseRequestedFields(fields));

    [Fact]
    public void Projection_requires_all_three_field_permissions_and_never_exposes_self_metadata()
    {
        var self = new SelfProfileDto("Private name", "Private bio", true,
            new ProfileContactEmailDto("private@example.invalid", ProfileContactEmailState.Verified), "\"private-revision\"");
        var result = OrganizationProfileInput.Project(self, new[] { "avatar", "biography" },
            new[] { "avatar", "displayName" }, new[] { "avatar", "contactEmail" });
        Assert.NotNull(result);
        Assert.Equal("{\"avatar\":true}", JsonSerializer.Serialize(result));
        Assert.Null(OrganizationProfileInput.Project(self, Array.Empty<string>(), new[] { "avatar" }, new[] { "avatar" }));
    }

    [Fact]
    public void Missing_values_cannot_produce_an_empty_successful_projection()
    {
        var self = new SelfProfileDto(null, null, false, new(null, ProfileContactEmailState.None), "\"0\"");
        string[] fields = [ProfileFields.DisplayName, ProfileFields.Biography];
        Assert.Null(OrganizationProfileInput.Project(self, fields, fields, fields));
        string[] avatar = [ProfileFields.Avatar];
        Assert.Equal("{\"avatar\":false}", JsonSerializer.Serialize(OrganizationProfileInput.Project(self, avatar, avatar, avatar)));
    }

    [Theory]
    [InlineData(ProfileContactEmailState.None)]
    [InlineData(ProfileContactEmailState.Pending)]
    public void Unverified_contact_is_unavailable_even_if_all_field_permissions_allow_it(ProfileContactEmailState state)
    {
        var self = new SelfProfileDto(null, null, false, new ProfileContactEmailDto("pending@example.invalid", state), "\"0\"");
        var fields = new[] { "contactEmail" };
        Assert.Null(OrganizationProfileInput.Project(self, fields, fields, fields));
    }
}
