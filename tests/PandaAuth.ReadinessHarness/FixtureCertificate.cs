using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace PandaAuth.ReadinessHarness;

public sealed record CertificateRequestInput(string RunId, string Directory, string Password);

public static class FixtureCertificate
{
    public static object Create(CertificateRequestInput input)
    {
        var directory = Path.GetFullPath(input.Directory);
        var temporary = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!Regex.IsMatch(input.RunId, "^[0-9a-f]{32}$") || Path.GetFileName(directory) != input.RunId ||
            !directory.StartsWith(temporary, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) ||
            input.Password.Length < 16 || !Directory.Exists(directory) ||
            File.GetAttributes(directory).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException("readiness_certificate_boundary_failed");
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=panda-auth-r1-" + input.RunId, rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var now = DateTimeOffset.UtcNow;
        using var root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(2));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost"); names.AddIpAddress(IPAddress.Loopback); names.AddIpAddress(IPAddress.IPv6Loopback);
        leafRequest.CertificateExtensions.Add(names.Build());
        using var issued = leafRequest.Create(root, now.AddMinutes(-5), now.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var leaf = issued.CopyWithPrivateKey(leafKey);
        WriteNew(Path.Combine(directory, "root.pem"), System.Text.Encoding.ASCII.GetBytes(root.ExportCertificatePem()));
        WriteNew(Path.Combine(directory, "proxy.pfx"), leaf.Export(X509ContentType.Pfx, input.Password));
        return new { schema = 1, valid = true, input.RunId };
    }

    private static void WriteNew(string path, byte[] bytes)
    {
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        output.Write(bytes);
        output.Flush(flushToDisk: true);
    }
}
