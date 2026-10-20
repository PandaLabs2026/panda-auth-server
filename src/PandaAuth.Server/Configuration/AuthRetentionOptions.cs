namespace PandaAuth.Server.Configuration;

public sealed class AuthRetentionOptions
{
    public bool Enabled { get; set; }
    public int SecurityEventRetentionDays { get; set; } = 90;
    public int TokenRetentionDays { get; set; } = 14;
    public void Validate()
    {
        if (Enabled && (SecurityEventRetentionDays is < 90 or > 3650 || TokenRetentionDays is < 14 or > 3650))
            throw new InvalidOperationException("Auth:Retention requires security-event days in [90,3650] and token days in [14,3650].");
    }
}
