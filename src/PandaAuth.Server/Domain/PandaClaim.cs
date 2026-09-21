namespace PandaAuth.Server.Domain;

public sealed class PandaUserClaim
{
    public long Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
}

public sealed class PandaRoleClaim
{
    public long Id { get; set; }
    public string RoleId { get; set; } = string.Empty;
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
}
