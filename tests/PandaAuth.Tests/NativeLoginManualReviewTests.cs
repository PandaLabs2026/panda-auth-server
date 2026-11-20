using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class NativeLoginManualReviewTests
{
    [ManualReviewFact]
    public async Task HostsTheWindowsManualReviewUntilTheOperatorReturnsAResult()
    {
        var reviewDirectory = Path.GetFullPath(Environment.GetEnvironmentVariable("PANDESK_AUTH_REVIEW_DIR")!);
        var executable = Path.GetFullPath(Environment.GetEnvironmentVariable("PANDESK_AUTH_GUI_EXE")!);
        var helperScript = Path.Combine(reviewDirectory, "pandesk-auth-review-code.ps1");
        Assert.Equal("pandesk-auth-isolated.exe", Path.GetFileName(executable));
        Assert.True(File.Exists(executable) && File.Exists(helperScript));

        using var authorityKey = RSA.Create(2048);
        using var serverKey = RSA.Create(2048);
        using var authority = NativeLoginDesktopTlsTests.CreateAuthority(authorityKey);
        using var generated = NativeLoginDesktopTlsTests.CreateServerCertificate(authority, serverKey);
        using var server = NativeLoginDesktopTlsTests.ImportForSchannel(generated);
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: NativeLoginRouteTests.Settings(),
            configureHost: factory => factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listener => listener.UseHttps(server))));
        await NativeLoginRouteTests.RegisterAsync(fixture, NativeLoginRouteTests.ClientId);
        var seed = RandomNumberGenerator.GetBytes(20);
        await fixture.EnableTotpAsync(fixtureSecret: seed);

        var addresses = fixture.Host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
        var endpoint = new Uri(Assert.Single(addresses.Addresses));
        Assert.Equal("127.0.0.1", endpoint.Host);
        Assert.Equal(Uri.UriSchemeHttps, endpoint.Scheme);
        var certificate = Path.Combine(reviewDirectory, "fixture-ca.cer");
        await File.WriteAllBytesAsync(certificate, authority.Export(X509ContentType.Cert));
        var appStart = new ProcessStartInfo(executable) { UseShellExecute = false };
        appStart.ArgumentList.Add("--auth-isolated");
        appStart.ArgumentList.Add(certificate);
        appStart.ArgumentList.Add(endpoint.Port.ToString(CultureInfo.InvariantCulture));
        appStart.Environment.Remove("PANDA_AUTH_TEST_POSTGRES");

        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var helperStart = new ProcessStartInfo(powershell) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Sta", "-File", helperScript })
            helperStart.ArgumentList.Add(arg);
        helperStart.Environment.Remove("PANDA_AUTH_TEST_POSTGRES");
        helperStart.Environment["PANDESK_REVIEW_PASSWORD"] = fixture.AdminPassword;
        helperStart.Environment["PANDESK_REVIEW_SEED"] = Convert.ToBase64String(seed);
        CryptographicOperations.ZeroMemory(seed);

        Process? app = null;
        Process? helper = null;
        try
        {
            helper = Process.Start(helperStart) ?? throw new InvalidOperationException("Cannot start the Pandesk fixture code window.");
            app = Process.Start(appStart) ?? throw new InvalidOperationException("Cannot start the Pandesk review window.");
            using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await RequireWindowAsync(app, startup.Token);
            await RequireWindowAsync(helper, startup.Token);
            Assert.Equal("Pandesk · 隔离认证联调", app.MainWindowTitle);
            Assert.Equal("Pandesk · 本机测试账号", helper.MainWindowTitle);

            var expires = DateTimeOffset.UtcNow.AddMinutes(15);
            var readyFile = Path.Combine(reviewDirectory, "review-ready.json");
            var pendingFile = readyFile + ".pending";
            await File.WriteAllTextAsync(pendingFile, JsonSerializer.Serialize(new { appPid = app.Id, helperPid = helper.Id, expiresUtc = expires }));
            File.Move(pendingFile, readyFile);

            var resultFile = Path.Combine(reviewDirectory, "operator-result.txt");
            var accountId = fixture.UserId;
            Evidence? previous = null;
            while (!File.Exists(resultFile) && DateTimeOffset.UtcNow < expires)
            {
                var observed = await ReadEvidenceAsync();
                if (previous != observed)
                {
                    var progress = Path.Combine(reviewDirectory, "review-progress.json");
                    await File.WriteAllTextAsync(progress + ".pending", JsonSerializer.Serialize(observed));
                    File.Move(progress + ".pending", progress, overwrite: true);
                    previous = observed;
                }
                await Task.Delay(800);
            }

            var outcome = File.Exists(resultFile) ? (await File.ReadAllTextAsync(resultFile)).Trim() : "unverified";
            Assert.Contains(outcome, new[] { "passed", "failed", "unverified" });
            var evidence = await ReadEvidenceAsync();
            await File.WriteAllTextAsync(Path.Combine(reviewDirectory, "review-result.json"),
                JsonSerializer.Serialize(new { outcome, evidence }));
            Assert.Equal("passed", outcome);
            Assert.True(evidence.RedeemedCodes >= 1, "The fixture did not observe an authorization code redemption for the operator account.");

            async Task<Evidence> ReadEvidenceAsync()
            {
                await using var db = fixture.Context();
                var passwordAttempts = await db.LoginLogs.CountAsync(log => log.ClientId == NativeLoginRouteTests.ClientId);
                var consumedChallenges = await db.MfaChallenges.CountAsync(challenge => challenge.Purpose == "native-login-totp" && challenge.ConsumedAt != null);
                var redeemedCodes = await db.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync(token =>
                    token.Subject == accountId && token.Type == TokenTypeIdentifiers.Private.AuthorizationCode && token.Status == Statuses.Redeemed);
                return new Evidence(passwordAttempts, consumedChallenges, redeemedCodes,
                    app.HasExited ? app.ExitCode : null, helper.HasExited ? helper.ExitCode : null);
            }
        }
        finally
        {
            await CloseOwnedWindowAsync(app);
            await CloseOwnedWindowAsync(helper);
            File.Delete(certificate);
        }
    }

    private sealed record Evidence(int PasswordAttempts, int ConsumedChallenges, int RedeemedCodes, int? PandeskExitCode, int? HelperExitCode);

    private static async Task RequireWindowAsync(Process process, CancellationToken cancellationToken)
    {
        while (!process.HasExited && process.MainWindowHandle == IntPtr.Zero)
        {
            await Task.Delay(200, cancellationToken);
            process.Refresh();
        }
        Assert.False(process.HasExited);
        Assert.True(process.Responding);
    }

    private static async Task CloseOwnedWindowAsync(Process? process)
    {
        if (process is null) return;
        using (process)
        {
            if (process.HasExited) return;
            process.CloseMainWindow();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await process.WaitForExitAsync(deadline.Token); }
            catch (OperationCanceledException) { process.Kill(); await process.WaitForExitAsync(); }
        }
    }

    private sealed class ManualReviewFact : FactAttribute
    {
        public ManualReviewFact()
        {
            if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDESK_AUTH_REVIEW_DIR"))
                || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDESK_AUTH_GUI_EXE"))
                || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES")))
                Skip = "Requires a Windows operator, the Pandesk review windows and disposable PostgreSQL.";
        }
    }
}
