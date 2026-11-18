using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;
using System.Text.Json;
using PandaAuth.Shared;
using Xunit;
using static PandaAuth.Tests.PandeskNativeProtocolTests;

namespace PandaAuth.Tests;

[AttributeUsage(AttributeTargets.Method)]
public sealed class PandeskIsolatedHostFactAttribute : FactAttribute
{
    internal const string DirectoryVariable = "PANDA_AUTH_PANDESK_HANDOFF_DIR";

    public PandeskIsolatedHostFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(DirectoryVariable)))
            Skip = "Start this fixture with tests/run-pandesk-isolated-host.sh.";
    }
}

public sealed class PandeskIsolatedHostTests
{
    [PandeskIsolatedHostFact]
    public async Task ServeTwoDevelopmentIssuersUntilStopped()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("The development fixture requires Linux.");
        var directory = new DirectoryInfo(Environment.GetEnvironmentVariable(PandeskIsolatedHostFactAttribute.DirectoryVariable)!);
        Assert.Equal(Environment.GetEnvironmentVariable("PANDALABS_TEMP_ROOT"), directory.Parent?.FullName);
        Assert.StartsWith("pandesk-handoff.", directory.Name);
        Assert.Null(directory.LinkTarget);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(directory.FullName));
        Assert.False(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES")));
        Assert.False(PostgresTestBoundary.SharedMode);

        const string tenantA = "t9841";
        const string tenantB = "t9842";
        using var certificateA = MakeCertificate(tenantA);
        using var certificateB = MakeCertificate(tenantB);
        var issuerA = LoopbackIssuer(tenantA);
        await using var fixtureA = await CreateIssuerAsync(tenantA, issuerA, certificateA);
        var issuerB = LoopbackIssuer(tenantB);
        await using var fixtureB = await CreateIssuerAsync(tenantB, issuerB, certificateB);
        var secretA = await ProvisionAsync(fixtureA, issuerA, certificateA);
        var secretB = await ProvisionAsync(fixtureB, issuerB, certificateB);

        var deadline = DateTimeOffset.UtcNow.AddMinutes(15);
        var manifest = new
        {
            expiresAtUtc = deadline,
            nativeClientId = PandeskNativeIdentity.ClientId,
            introspectionClientId = PandeskNativeIdentity.IntrospectionClientId,
            readScope = PandeskNativeIdentity.ReadScope,
            audience = PandeskNativeIdentity.Audience,
            issuers = new[]
            {
                new { tenant = tenantA, issuer = issuerA, subject = fixtureA.UserId, username = "security-admin",
                    password = fixtureA.AdminPassword, introspectionSecret = secretA, certificate = tenantA + ".pem", totp = tenantA + ".totp" },
                new { tenant = tenantB, issuer = issuerB, subject = fixtureB.UserId, username = "security-admin",
                    password = fixtureB.AdminPassword, introspectionSecret = secretB, certificate = tenantB + ".pem", totp = tenantB + ".totp" },
            },
        };
        var manifestPath = Path.Combine(directory.FullName, "handoff.json");
        var stopPath = Path.Combine(directory.FullName, "stop");
        var otpA = Path.Combine(directory.FullName, tenantA + ".totp");
        var otpB = Path.Combine(directory.FullName, tenantB + ".totp");
        var pemA = Path.Combine(directory.FullName, tenantA + ".pem");
        var pemB = Path.Combine(directory.FullName, tenantB + ".pem");
        try
        {
            WritePrivate(pemA, certificateA.ExportCertificatePem());
            WritePrivate(pemB, certificateB.ExportCertificatePem());
            WritePrivate(otpA, fixtureA.CurrentTotpCode());
            WritePrivate(otpB, fixtureB.CurrentTotpCode());
            WritePrivate(manifestPath, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
            while (DateTimeOffset.UtcNow < deadline && !File.Exists(stopPath))
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
                WritePrivate(otpA, fixtureA.CurrentTotpCode());
                WritePrivate(otpB, fixtureB.CurrentTotpCode());
            }
        }
        finally
        {
            foreach (var path in new[] { manifestPath, otpA, otpB, pemA, pemB })
            {
                File.Delete(path);
                File.Delete(path + ".tmp");
            }
        }
    }

    private static async Task<string> ProvisionAsync(SecurityProtocolFixture fixture, Uri issuer,
        X509Certificate2 certificate)
    {
        await fixture.EnableTotpAsync(administrator: false);
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await RegisterAsync(fixture, secret);
        using var browser = CreateBrowser(issuer, certificate);
        await AssertDiscoveryAsync(browser, issuer);
        return secret;
    }

    [SupportedOSPlatform("linux")]
    private static void WritePrivate(string path, string content)
    {
        var temporaryPath = path + ".tmp";
        using (var stream = new FileStream(temporaryPath, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        }))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(content);
        }
        File.Move(temporaryPath, path, overwrite: true);
    }
}
