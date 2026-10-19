namespace PandaAuth.Server.Domain;

/// <summary>Persistent revocation marker for a first-party Admin or Me cookie session.</summary>
public sealed class SessionRevocation
{
    public string ClientId { get; set; } = string.Empty;

    public string SessionIdHash { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
}
