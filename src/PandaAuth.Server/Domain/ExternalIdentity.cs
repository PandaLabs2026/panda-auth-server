namespace PandaAuth.Server.Domain;

/// <summary>Provider-neutral external identity link. Provider credentials are never stored here.</summary>
public sealed class ExternalIdentity
{
    public long Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string ProviderSubject { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? EmailSnapshot { get; set; }
    public DateTimeOffset LinkedAt { get; set; }
    public DateTimeOffset? UnlinkedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
