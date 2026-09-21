using PandaAuth.Shared;

namespace PandaAuth.Server.Domain;

// Persistent IDs are also the OpenIddict subject. Never regenerate them on migration.
public sealed class PandaUser
{
    public const string AdminRole = "admin";
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string? UserName { get; set; }
    public string? NormalizedUserName { get; set; }
    public string? Email { get; set; }
    public string? NormalizedEmail { get; set; }
    // Migrated users may still sign in while false. Sensitive account workflows gate on it.
    public bool EmailConfirmed { get; set; }
    public string? PasswordHash { get; set; }
    // Credential material is deliberately not migrated. A preserved true value blocks
    // password-only sign-in until an administrator resets/reconfigures MFA.
    public bool TwoFactorEnabled { get; set; }
    public string? SecurityStamp { get; set; } = Guid.NewGuid().ToString();
    public string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
    public bool LockoutEnabled { get; set; } = true;
    public DateTimeOffset? LockoutEnd { get; set; }
    public int AccessFailedCount { get; set; }
    public string? Nickname { get; set; }
    public string? AvatarUrl { get; set; }
    public UserStatus Status { get; set; } = UserStatus.Active;
    public RegisterChannel RegisterChannel { get; set; } = RegisterChannel.Password;
    public string? Region { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class PandaRole
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string? Name { get; set; }
    public string? NormalizedName { get; set; }
    public string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
}

public sealed class PandaUserRole
{
    public string UserId { get; set; } = null!;
    public string RoleId { get; set; } = null!;
}
