using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class NativeLoginDesktopTlsTests
{
    [DesktopTlsFact]
    public async Task RustTransport_CompletesNativeAuthenticationThroughKestrelOverTls()
    {
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
        var port = GetPort(fixture);

        var directory = Directory.CreateTempSubdirectory("pandesk-auth-tls-");
        var certificate = Path.Combine(directory.FullName, "fixture-ca.cer");
        try
        {
            await File.WriteAllBytesAsync(certificate, authority.Export(X509ContentType.Cert));
            var start = CreateDesktopTest("isolated_https_roundtrip");
            SetDesktopFixture(start, "PANDESK_FIXTURE", certificate, port, fixture);
            await RunDesktopTestAsync(start);
            if (Environment.GetEnvironmentVariable("PANDESK_AUTH_GUI_EXE") is { Length: > 0 } windowExe)
                await VerifyNativeWindowAsync(windowExe, certificate, port);
        }
        finally
        {
            File.Delete(certificate);
            directory.Delete();
        }
    }

    [DesktopTlsFact]
    public async Task RustTransport_SeparatesSameEmailAccountsAcrossTwoNativeIssuers()
    {
        const string secondTenant = "t9877";
        using var firstAuthorityKey = RSA.Create(2048);
        using var secondAuthorityKey = RSA.Create(2048);
        using var firstServerKey = RSA.Create(2048);
        using var secondServerKey = RSA.Create(2048);
        using var firstAuthority = CreateAuthority(firstAuthorityKey);
        using var secondAuthority = CreateAuthority(secondAuthorityKey);
        using var firstGenerated = CreateServerCertificate(firstAuthority, firstServerKey);
        using var secondGenerated = CreateServerCertificate(secondAuthority, secondServerKey, NativeLoginRouteTests.FixtureHost(secondTenant));
        using var firstServer = ImportForSchannel(firstGenerated);
        using var secondServer = ImportForSchannel(secondGenerated);
        await using var first = await SecurityProtocolFixture.CreateAsync(
            settings: NativeLoginRouteTests.Settings(),
            configureHost: factory => factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listener => listener.UseHttps(firstServer))));
        await using var second = await SecurityProtocolFixture.CreateAsync(
            settings: NativeLoginRouteTests.Settings(secondTenant),
            configureHost: factory => factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listener => listener.UseHttps(secondServer))));
        Assert.NotEqual(first.UserId, second.UserId);
        await NativeLoginRouteTests.RegisterAsync(first, NativeLoginRouteTests.ClientId);
        await NativeLoginRouteTests.RegisterAsync(second, NativeLoginRouteTests.ClientId, secondTenant);
        var firstSeed = RandomNumberGenerator.GetBytes(20);
        var secondSeed = RandomNumberGenerator.GetBytes(20);
        var firstPort = GetPort(first);
        var secondPort = GetPort(second);
        Assert.NotEqual(firstPort, secondPort);

        var directory = Directory.CreateTempSubdirectory("pandesk-dual-issuer-");
        var firstCertificate = Path.Combine(directory.FullName, "first-ca.cer");
        var secondCertificate = Path.Combine(directory.FullName, "second-ca.cer");
        try
        {
            await first.EnableTotpAsync(administrator: false, fixtureSecret: firstSeed);
            await second.EnableTotpAsync(administrator: false, fixtureSecret: secondSeed);
            await File.WriteAllBytesAsync(firstCertificate, firstAuthority.Export(X509ContentType.Cert));
            await File.WriteAllBytesAsync(secondCertificate, secondAuthority.Export(X509ContentType.Cert));
            var start = CreateDesktopTest("isolated_dual_issuer_roundtrip");
            SetDesktopFixture(start, "PANDESK_FIXTURE", firstCertificate, firstPort, first);
            SetDesktopFixture(start, "PANDESK_FIXTURE_SECOND", secondCertificate, secondPort, second);
            await RunDesktopTestAsync(start);
            var evidence = Environment.GetEnvironmentVariable("PANDESK_AUTH_UI_EVIDENCE_DIR");
            var windowExe = Environment.GetEnvironmentVariable("PANDESK_AUTH_GUI_EXE");
            if (!string.IsNullOrWhiteSpace(evidence)) Assert.False(string.IsNullOrWhiteSpace(windowExe));
            if (windowExe is { Length: > 0 })
                await VerifyNativeWindowAsync(windowExe, firstCertificate, firstPort, secondCertificate, secondPort,
                    string.IsNullOrWhiteSpace(evidence) ? null : app => VerifyOrganizationSwitchAsync(app, evidence, first, second, firstSeed, secondSeed));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstSeed);
            CryptographicOperations.ZeroMemory(secondSeed);
            File.Delete(firstCertificate);
            File.Delete(secondCertificate);
            directory.Delete();
        }
    }

    private static async Task VerifyOrganizationSwitchAsync(Process app, string evidenceDirectory,
        SecurityProtocolFixture first, SecurityProtocolFixture second, byte[] firstSeed, byte[] secondSeed)
    {
        Assert.True(Path.IsPathFullyQualified(evidenceDirectory) && Directory.Exists(evidenceDirectory));
        var script = Path.Combine(AppContext.BaseDirectory, "Fixtures", "Pandesk", "pandesk-dual-window-review.ps1");
        Assert.True(File.Exists(script));
        var beforeA = await CountRedeemedCodesAsync(first);
        var beforeB = await CountRedeemedCodesAsync(second);
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var start = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Sta", "-File", script,
                     app.Id.ToString(CultureInfo.InvariantCulture), evidenceDirectory })
            start.ArgumentList.Add(arg);
        start.Environment.Remove("PANDA_AUTH_TEST_POSTGRES");
        start.Environment["PANDESK_REVIEW_PASSWORD_A"] = first.AdminPassword;
        start.Environment["PANDESK_REVIEW_PASSWORD_B"] = second.AdminPassword;
        start.Environment["PANDESK_REVIEW_SEED_A"] = Convert.ToBase64String(firstSeed);
        start.Environment["PANDESK_REVIEW_SEED_B"] = Convert.ToBase64String(secondSeed);
        using var driver = Process.Start(start) ?? throw new InvalidOperationException("Cannot start Windows UI verification.");
        var stdout = driver.StandardOutput.ReadToEndAsync();
        var stderr = driver.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try { await driver.WaitForExitAsync(deadline.Token); }
        finally { if (!driver.HasExited) { driver.Kill(entireProcessTree: true); await driver.WaitForExitAsync(); } }
        Assert.True(driver.ExitCode == 0, await stdout + await stderr);
        var afterA = await CountRedeemedCodesAsync(first) - beforeA;
        var afterB = await CountRedeemedCodesAsync(second) - beforeB;
        Assert.Equal(2, afterA);
        Assert.Equal(1, afterB);
        Assert.False(app.HasExited);
        await File.WriteAllTextAsync(Path.Combine(evidenceDirectory, "same-window-issuer-evidence.json"),
            System.Text.Json.JsonSerializer.Serialize(new { windowPid = app.Id, firstIssuerRedemptions = afterA, secondIssuerRedemptions = afterB }));
        Console.WriteLine($"One Pandesk window ({app.Id}) redeemed {afterA} codes at issuer A and {afterB} at issuer B.");
    }

    private static async Task<int> CountRedeemedCodesAsync(SecurityProtocolFixture fixture)
    {
        await using var db = fixture.Context();
        return await db.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync(token => token.Subject == fixture.UserId &&
            token.Type == TokenTypeIdentifiers.Private.AuthorizationCode && token.Status == Statuses.Redeemed);
    }

    private static int GetPort(SecurityProtocolFixture fixture)
    {
        var listener = fixture.Host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
        var endpoint = new Uri(Assert.Single(listener.Addresses));
        Assert.Equal(Uri.UriSchemeHttps, endpoint.Scheme);
        Assert.Equal("127.0.0.1", endpoint.Host);
        return endpoint.Port;
    }

    private static ProcessStartInfo CreateDesktopTest(string test)
    {
        var executable = Environment.GetEnvironmentVariable("PANDESK_AUTH_CLIENT_TEST_EXE")!;
        Assert.True(Path.IsPathFullyQualified(executable) && File.Exists(executable));
        Assert.Equal("pandesk-auth-client-test.exe", Path.GetFileName(executable));
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        start.ArgumentList.Add($"native_auth::tests::{test}");
        start.ArgumentList.Add("--exact");
        start.ArgumentList.Add("--ignored");
        start.Environment.Remove("PANDA_AUTH_TEST_POSTGRES");
        return start;
    }

    private static void SetDesktopFixture(ProcessStartInfo start, string prefix, string certificate, int port, SecurityProtocolFixture fixture)
    {
        start.Environment[$"{prefix}_CERT"] = certificate;
        start.Environment[$"{prefix}_PORT"] = port.ToString(CultureInfo.InvariantCulture);
        start.Environment[$"{prefix}_PASSWORD"] = fixture.AdminPassword;
        start.Environment[$"{prefix}_OTP"] = fixture.CurrentTotpCode();
    }

    private static async Task RunDesktopTestAsync(ProcessStartInfo start)
    {
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the Pandesk transport test.");
        var stdout = child.StandardOutput.ReadToEndAsync();
        var stderr = child.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await child.WaitForExitAsync(deadline.Token); }
        finally { if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(); } }
        Assert.True(child.ExitCode == 0, await stdout + await stderr);
        Assert.Contains("1 passed", await stdout);
    }

    internal static X509Certificate2 CreateAuthority(RSA key)
    {
        var request = new CertificateRequest("CN=Pandesk local fixture CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(1));
    }

    internal static X509Certificate2 CreateServerCertificate(X509Certificate2 authority, RSA key, string? host = null)
    {
        host ??= NativeLoginRouteTests.Host;
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(host);
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

    private static async Task VerifyNativeWindowAsync(string executable, string certificate, int port,
        string? secondCertificate = null, int secondPort = 0, Func<Process, Task>? interact = null)
    {
        Assert.True(Path.IsPathFullyQualified(executable) && File.Exists(executable));
        Assert.Equal("pandesk-auth-isolated.exe", Path.GetFileName(executable));
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        start.ArgumentList.Add("--auth-isolated");
        start.ArgumentList.Add(certificate);
        start.ArgumentList.Add(port.ToString(CultureInfo.InvariantCulture));
        if (secondCertificate is not null)
        {
            start.ArgumentList.Add(secondCertificate);
            start.ArgumentList.Add(secondPort.ToString(CultureInfo.InvariantCulture));
        }
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
            if (interact is not null) await interact(window);
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
