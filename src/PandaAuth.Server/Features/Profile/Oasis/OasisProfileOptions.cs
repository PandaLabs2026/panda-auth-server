using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace PandaAuth.Server.Features.Profile.Oasis;

// Private consumer configuration; wire contract is owned by Oasis #150.
internal sealed class OasisProfileOptions
{
    public bool Enabled { get; set; }
    public string Endpoint { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecretFile { get; set; } = "";
    public Guid[] OrganizationKeys { get; set; } = [];
    internal string? ClientSecret { get; private set; }

    internal void ValidateAndLoad(string? currentIssuer)
    {
        if (!Enabled) return;
        if (!ValidHttps(Issuer, out _) || !Issuer.EndsWith('/')
            || !string.Equals(Issuer, currentIssuer?.TrimEnd('/') + "/", StringComparison.Ordinal)
            || !ValidHttps(Endpoint, out var endpoint) || endpoint!.AbsolutePath != OasisProfileAccessClient.Route
            || ClientId.Length is < 1 or > 450 || ClientId.Any(char.IsWhiteSpace) || ClientId.Any(char.IsControl)
            || ClientId == OasisProfileAccessClient.Audience
            || OrganizationKeys.Length == 0 || OrganizationKeys.Contains(Guid.Empty)
            || OrganizationKeys.Distinct().Count() != OrganizationKeys.Length)
            throw Invalid();
        ClientSecret = ReadSecret(ClientSecretFile);
    }

    private static bool ValidHttps(string value, out Uri? uri)
        => Uri.TryCreate(value, UriKind.Absolute, out uri) && value.Length <= 2048
           && uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0
           && uri.Query.Length == 0 && uri.Fragment.Length == 0;

    // Same private-file boundary as the owner resource's separate introspection credential.
    private static string ReadSecret(string path)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path)) throw Invalid();
            var info = new FileInfo(path);
            if (!info.Exists || info.LinkTarget is not null || info.Length is < 32 or > 4096) throw Invalid();
            for (var parent = info.Directory; parent is not null; parent = parent.Parent)
                if (parent.LinkTarget is not null) throw Invalid();
            if (!OperatingSystem.IsWindows())
            {
                var mode = File.GetUnixFileMode(path);
                if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0) throw Invalid();
            }
            else
            {
                var user = WindowsIdentity.GetCurrent().User;
                foreach (FileSystemAccessRule rule in info.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference != user
                        && !((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.LocalSystemSid)
                        && !((SecurityIdentifier)rule.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) throw Invalid();
            }
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var bytes = new byte[4097];
            var length = 0;
            while (length < bytes.Length)
            {
                var read = stream.Read(bytes.AsSpan(length));
                if (read == 0) break;
                length += read;
            }
            if (length > 4096) throw Invalid();
            var secret = new UTF8Encoding(false, true).GetString(bytes, 0, length).Trim();
            if (secret.Length is < 32 or > 1024 || secret.Any(char.IsControl) || secret.Any(char.IsWhiteSpace)) throw Invalid();
            return secret;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw Invalid(); // Do not include the file path or credential in exceptions.
        }
    }

    private static InvalidOperationException Invalid() => new("Oasis profile registration is invalid.");
}

internal sealed record OasisMembershipProof(Guid OrganizationKey, Guid MemberKey,
    string RequesterId, string TargetId, IReadOnlyList<string> AllowedFields);
