namespace PandaAuth.Server.Domain;

/// <summary>Explicit consent for one registered organization; retained empty rows preserve revision history.</summary>
public sealed class ProfileOrganizationVisibility
{
    public required string UserId { get; set; }
    public Guid OrganizationKey { get; set; }
    public int Fields { get; set; }
    public required string Revision { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
