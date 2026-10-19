using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace PandaAuth.Server.Infrastructure.Messaging;

/// <summary>
/// Builds the HTTP handler for the notify gateway: optional producer client
/// certificate plus optional custom server CA. The gateway runs with a private
/// CA in production, so system trust alone is not enough.
/// </summary>
public static class NotifyTransportHandler
{
    public static HttpClientHandler Create(EmailOptions options)
    {
        var handler = new HttpClientHandler();
        if (!string.IsNullOrWhiteSpace(options.NotifyClientCertificateFile))
        {
            var password = string.IsNullOrWhiteSpace(options.NotifyClientCertificatePasswordFile)
                ? null
                : File.ReadAllText(options.NotifyClientCertificatePasswordFile).Trim();
            handler.ClientCertificates.Add(
                X509CertificateLoader.LoadPkcs12FromFile(options.NotifyClientCertificateFile, password));
        }

        if (!string.IsNullOrWhiteSpace(options.NotifyServerCaFile))
        {
            var ca = X509CertificateLoader.LoadCertificateFromFile(options.NotifyServerCaFile);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
            {
                if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                {
                    return false;
                }

                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(certificate);
            };
        }

        return handler;
    }
}
