using PandaAuth.Shared;

namespace PandaAuth.Server.Domain;

/// <summary>Private profile, separate from login identity and credential recovery.</summary>
public sealed class UserProfile
{
    public required string UserId { get; set; }
    public string? DisplayName { get; set; }
    public string? Biography { get; set; }
    public string? ContactEmail { get; set; }
    public ProfileContactEmailState ContactEmailState { get; set; }
    // Stored without HTTP quotes; the API exposes this as a strong ETag.
    public required string Revision { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>Only normalized PNG bytes belong here; upload/decoder validation precedes persistence.</summary>
public sealed class ProfileAvatar
{
    public const string MediaType = "image/png";
    public required string UserId { get; set; }
    public required byte[] Bytes { get; set; }
    public int Width { get; set; }
    public int Height { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
