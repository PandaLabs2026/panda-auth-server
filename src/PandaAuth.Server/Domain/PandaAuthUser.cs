using Microsoft.AspNetCore.Identity;
using PandaAuth.Shared;

namespace PandaAuth.Server.Domain;

// UserStatus / RegisterChannel 枚举定义在 PandaAuth.Shared（跨进程契约）。

public class PandaAuthUser : IdentityUser
{
    public const string AdminRole = "admin";

    public string? Nickname { get; set; }

    public string? AvatarUrl { get; set; }

    public UserStatus Status { get; set; } = UserStatus.Active;

    public RegisterChannel RegisterChannel { get; set; } = RegisterChannel.Password;

    /// <summary>用户所属区域标签（P3 全球化多实例时启用，如 CN / GLOBAL）。</summary>
    public string? Region { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public class PandaAuthRole : IdentityRole;
