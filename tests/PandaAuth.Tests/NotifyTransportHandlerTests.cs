using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PandaAuth.Server.Infrastructure.Messaging;
using Xunit;

namespace PandaAuth.Tests;

public sealed class NotifyTransportHandlerTests
{
    [Fact]
    public void Server_ca_is_the_only_trust_anchor()
    {
        using var ca = CreateCertificateAuthority();
        using var server = CreateServerCertificate(ca);
        using var rogue = CreateCertificateAuthority();
        var caFile = WriteTemp(ca.RawData, ".der");

        try
        {
            using var handler = NotifyTransportHandler.Create(new EmailOptions { NotifyServerCaFile = caFile });
            var validate = handler.ServerCertificateCustomValidationCallback;

            Assert.NotNull(validate);
            Assert.True(validate(null!, server, null, SslPolicyErrors.None));
            Assert.False(validate(null!, rogue, null, SslPolicyErrors.None));
            Assert.False(validate(null!, server, null, SslPolicyErrors.RemoteCertificateNameMismatch));
        }
        finally
        {
            File.Delete(caFile);
        }
    }

    [Fact]
    public void Producer_pfx_is_loaded_as_a_client_certificate()
    {
        using var certificate = CreateCertificateAuthority();
        var pfxFile = WriteTemp(certificate.Export(X509ContentType.Pfx, "secret")!, ".pfx");
        var passwordFile = WriteTemp("secret"u8.ToArray(), ".pass");

        try
        {
            using var handler = NotifyTransportHandler.Create(new EmailOptions
            {
                NotifyClientCertificateFile = pfxFile,
                NotifyClientCertificatePasswordFile = passwordFile,
            });

            Assert.Single(handler.ClientCertificates);
            Assert.Null(handler.ServerCertificateCustomValidationCallback);
        }
        finally
        {
            File.Delete(pfxFile);
            File.Delete(passwordFile);
        }
    }

    private static X509Certificate2 CreateCertificateAuthority()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=notify-test-ca", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 CreateServerCertificate(X509Certificate2 issuer)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var alternativeNames = new SubjectAlternativeNameBuilder();
        alternativeNames.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(alternativeNames.Build());
        return request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddHours(-12),
            DateTimeOffset.UtcNow.AddHours(12),
            RandomNumberGenerator.GetBytes(8));
    }

    private static string WriteTemp(byte[] content, string extension)
    {
        var path = Path.Combine(Path.GetTempPath(), $"notify-{Guid.NewGuid():N}{extension}");
        File.WriteAllBytes(path, content);
        return path;
    }
}
