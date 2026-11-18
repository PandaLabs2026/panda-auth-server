using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace PandaAuth.Tests;

public sealed class NativeLoginDesktopTlsTests
{
    [DesktopTlsFact]
    public async Task RustTransport_CompletesNativeAuthenticationThroughKestrelOverTls()
    {
        var executable = Environment.GetEnvironmentVariable("PANDESK_AUTH_CLIENT_TEST_EXE")!;
        Assert.True(Path.IsPathFullyQualified(executable) && File.Exists(executable));
        Assert.Equal("pandesk-auth-client-test.exe", Path.GetFileName(executable));
        using var authorityKey = RSA.Create(2048);
        using var serverKey = RSA.Create(2048);
        using var authority = CreateAuthority(authorityKey);
        using var generated = CreateServerCertificate(authority, serverKey);
        using var server = ImportForSchannel(generated);
        await using var fixture = await SecurityProtocolFixture.CreateAsync(
            configure: services => services.AddLogging(logging => logging.AddSimpleConsole()
                .AddFilter((category, level) => category?.StartsWith("Microsoft.AspNetCore.Server.Kestrel", StringComparison.Ordinal) == true
                    && level >= LogLevel.Debug)),
            settings: NativeLoginRouteTests.Settings(),
            configureHost: factory => factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listener => listener.UseHttps(server))));
        await NativeLoginRouteTests.RegisterAsync(fixture, NativeLoginRouteTests.ClientId);
        await fixture.EnableTotpAsync();
        var listener = fixture.Host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
        var endpoint = new Uri(Assert.Single(listener.Addresses));
        Assert.Equal(Uri.UriSchemeHttps, endpoint.Scheme);
        Assert.Equal("127.0.0.1", endpoint.Host);

        var directory = Directory.CreateTempSubdirectory("pandesk-auth-tls-");
        var certificate = Path.Combine(directory.FullName, "fixture-ca.cer");
        try
        {
            await File.WriteAllBytesAsync(certificate, authority.Export(X509ContentType.Cert));
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            start.ArgumentList.Add("native_auth::tests::isolated_https_roundtrip");
            start.ArgumentList.Add("--exact");
            start.ArgumentList.Add("--ignored");
            start.Environment["PANDESK_FIXTURE_CERT"] = certificate;
            start.Environment["PANDESK_FIXTURE_PORT"] = endpoint.Port.ToString(CultureInfo.InvariantCulture);
            start.Environment["PANDESK_FIXTURE_PASSWORD"] = fixture.AdminPassword;
            start.Environment["PANDESK_FIXTURE_OTP"] = fixture.CurrentTotpCode();
            start.Environment.Remove("PANDA_AUTH_TEST_POSTGRES");
            using var child = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the Pandesk transport test.");
            var stdout = child.StandardOutput.ReadToEndAsync();
            var stderr = child.StandardError.ReadToEndAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try { await child.WaitForExitAsync(deadline.Token); }
            finally { if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(); } }
            var output = await stdout;
            var error = await stderr;
            Assert.True(child.ExitCode == 0, output + error);
            Assert.Contains("1 passed", output);
            if (Environment.GetEnvironmentVariable("PANDESK_AUTH_GUI_EXE") is { Length: > 0 } windowExe)
                await VerifyNativeWindowAsync(windowExe, certificate, endpoint.Port);
        }
        finally
        {
            File.Delete(certificate);
            directory.Delete();
        }
    }

    internal static X509Certificate2 CreateAuthority(RSA key)
    {
        var request = new CertificateRequest("CN=Pandesk local fixture CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(1));
    }

    internal static X509Certificate2 CreateServerCertificate(X509Certificate2 authority, RSA key)
    {
        var request = new CertificateRequest($"CN={NativeLoginRouteTests.Host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(NativeLoginRouteTests.Host);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using var certificate = request.Create(authority, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
        return certificate.CopyWithPrivateKey(key);
    }

    internal static X509Certificate2 ImportForSchannel(X509Certificate2 certificate)
    {
        // Schannel cannot bind the in-memory ephemeral key from CertificateRequest.
        // The non-persistent user-key import is released on Dispose and never saved as a PFX file.
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var pfx = certificate.Export(X509ContentType.Pkcs12, password);
        try { return X509CertificateLoader.LoadPkcs12(pfx, password, X509KeyStorageFlags.UserKeySet); }
        finally { CryptographicOperations.ZeroMemory(pfx); }
    }

    private static async Task VerifyNativeWindowAsync(string executable, string certificate, int port)
    {
        Assert.True(Path.IsPathFullyQualified(executable) && File.Exists(executable));
        Assert.Equal("pandesk-auth-isolated.exe", Path.GetFileName(executable));
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        start.ArgumentList.Add("--auth-isolated");
        start.ArgumentList.Add(certificate);
        start.ArgumentList.Add(port.ToString(CultureInfo.InvariantCulture));
        start.Environment.Remove("PANDA_AUTH_TEST_POSTGRES");
        using var window = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the Pandesk window.");
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            while (!window.HasExited && window.MainWindowHandle == IntPtr.Zero)
            {
                await Task.Delay(200, deadline.Token);
                window.Refresh();
            }
            Assert.False(window.HasExited);
            Assert.Equal("Pandesk · 隔离认证联调", window.MainWindowTitle);
            Assert.True(window.Responding);
            Console.WriteLine($"Pandesk window: {window.MainWindowTitle}; responding; PID {window.Id}.");
        }
        finally
        {
            if (!window.HasExited)
            {
                window.CloseMainWindow();
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { await window.WaitForExitAsync(deadline.Token); }
                catch (OperationCanceledException) { window.Kill(); await window.WaitForExitAsync(); }
            }
        }
    }

    private sealed class DesktopTlsFact : FactAttribute
    {
        public DesktopTlsFact()
        {
            if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDESK_AUTH_CLIENT_TEST_EXE"))
                || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES")))
                Skip = "Requires the Windows Rust transport test and disposable PostgreSQL fixture.";
        }
    }
}
