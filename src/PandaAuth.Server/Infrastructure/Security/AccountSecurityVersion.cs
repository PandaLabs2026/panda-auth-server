using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using PandaAuth.Server.Domain;
using PandaAuth.Shared;

namespace PandaAuth.Server.Infrastructure.Security;

internal static class AccountSecurityVersion
{
    internal static string From(PandaUser user)
    {
        if (string.IsNullOrEmpty(user.Id) || string.IsNullOrEmpty(user.SecurityStamp))
            throw new InvalidOperationException("Account security stamp is required.");
        return Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes("PandaAuth.SecurityVersion.v1\0" + user.Id + "\0" + user.SecurityStamp)));
    }

    internal static bool Matches(ClaimsPrincipal? principal, PandaUser? user)
    {
        var versions = principal?.FindAll(PandaAuthClaims.SecurityVersion).ToArray() ?? [];
        return user is { Status: UserStatus.Active } && !string.IsNullOrEmpty(user.SecurityStamp)
            && versions.Length == 1 && versions[0].Value == From(user);
    }

    internal static async Task<bool> IsCurrentAsync(ClaimsPrincipal principal, UserService users)
    {
        var subjects = principal.FindAll("sub").ToArray();
        return subjects.Length == 1 && Matches(principal, await users.FindByIdAsync(subjects[0].Value));
    }
}
