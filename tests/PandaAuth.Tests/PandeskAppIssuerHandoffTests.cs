using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

[AttributeUsage(AttributeTargets.Method)]
public sealed class PandeskAppIssuerHandoffFactAttribute : FactAttribute
{
    internal const string DirectoryVariable = "PANDA_AUTH_PANDESK_APP_HANDOFF_DIR";

    public PandeskAppIssuerHandoffFactAttribute()
    {
        if (!OperatingSystem.IsLinux() || string.IsNullOrEmpty(Environment.GetEnvironmentVariable(DirectoryVariable)))
            Skip = "This fixture requires an explicit private task directory on Linux.";
    }
}

public sealed class PandeskAppIssuerHandoffTests
{
    [PandeskAppIssuerHandoffFact]
    public async Task ServeUntilStopped()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The local handoff fixture requires Linux.");
        var directory = new DirectoryInfo(Environment.GetEnvironmentVariable(PandeskAppIssuerHandoffFactAttribute.DirectoryVariable)!);
        Assert.Equal(Environment.GetEnvironmentVariable("PANDALABS_TEMP_ROOT"), directory.Parent?.FullName);
        Assert.StartsWith("pandesk-app-handoff.", directory.Name);
        Assert.Null(directory.LinkTarget);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(directory.FullName));
        Assert.Empty(directory.EnumerateFileSystemInfos());
        Assert.False(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES")));
        Assert.False(PostgresTestBoundary.SharedMode);

        const string firstTenant = "t9876";
        const string secondTenant = "t9877";
        using var firstAuthorityKey = RSA.Create(2048);
        using var secondAuthorityKey = RSA.Create(2048);
        using var firstServerKey = RSA.Create(2048);
        using var secondServerKey = RSA.Create(2048);
        using var firstAuthority = NativeLoginDesktopTlsTests.CreateAuthority(firstAuthorityKey);
        using var secondAuthority = NativeLoginDesktopTlsTests.CreateAuthority(secondAuthorityKey);
        using var firstServer = NativeLoginDesktopTlsTests.CreateServerCertificate(firstAuthority, firstServerKey,
            NativeLoginRouteTests.FixtureHost(firstTenant));
        using var secondServer = NativeLoginDesktopTlsTests.CreateServerCertificate(secondAuthority, secondServerKey,
            NativeLoginRouteTests.FixtureHost(secondTenant));
        await using var first = await NativeLoginBusinessTokenTests.CreateIssuerAsync(firstTenant, firstServer);
        await using var second = await NativeLoginBusinessTokenTests.CreateIssuerAsync(secondTenant, secondServer);

        var ownedFiles = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var firstMetadata = await PublishIssuerAsync(firstTenant, firstAuthority, first);
            var secondMetadata = await PublishIssuerAsync(secondTenant, secondAuthority, second);
            var deadline = DateTimeOffset.UtcNow.AddMinutes(15);
            WritePrivate("handoff.json", JsonSerializer.Serialize(new
            {
                purpose = "synthetic-auth-fixture",
                expiresAtUtc = deadline,
                clientId = NativeLoginRouteTests.ClientId,
                scope = PandeskCustomerRead.Scope,
                audience = PandeskCustomerRead.Audience,
                introspectionAudience = PandeskCustomerRead.IntrospectionAudience,
                issuers = new[] { firstMetadata, secondMetadata },
            }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));

            var stop = Path.Combine(directory.FullName, "stop");
            while (DateTimeOffset.UtcNow < deadline && !File.Exists(stop))
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
                if (DateTimeOffset.UtcNow >= deadline || File.Exists(stop)) break;
                WritePrivate(firstMetadata.TotpFile, first.CurrentTotpCode());
                WritePrivate(secondMetadata.TotpFile, second.CurrentTotpCode());
            }
        }
        finally
        {
            foreach (var path in ownedFiles) File.Delete(path);
        }

        async Task<IssuerMetadata> PublishIssuerAsync(string tenant, X509Certificate2 authority, SecurityProtocolFixture fixture)
        {
            var secret = await NativeLoginBusinessTokenTests.RegisterAsync(fixture, tenant);
            var host = NativeLoginRouteTests.FixtureHost(tenant);
            var ca = tenant + ".pem";
            var totp = tenant + ".totp";
            var login = tenant + ".login.json";
            var introspection = tenant + ".introspection.json";
            WritePrivate(ca, authority.ExportCertificatePem());
            WritePrivate(totp, fixture.CurrentTotpCode());
            WritePrivate(login, JsonSerializer.Serialize(new { subject = fixture.UserId, username = "security-admin", password = fixture.AdminPassword }));
            WritePrivate(introspection, JsonSerializer.Serialize(new { clientId = PandeskCustomerRead.IntrospectionClientId, clientSecret = secret }));
            return new(tenant, $"https://{host}/", NativeLoginDesktopTlsTests.GetPort(fixture), ca,
                authority.GetCertHashString(HashAlgorithmName.SHA256), login, totp, introspection);
        }

        [SupportedOSPlatform("linux")]
        void WritePrivate(string name, string content)
        {
            var path = Path.Combine(directory.FullName, name);
            var temporary = path + ".tmp";
            using (var stream = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                ownedFiles.Add(temporary);
                using var writer = new StreamWriter(stream);
                writer.Write(content);
            }
            File.Move(temporary, path, overwrite: ownedFiles.Contains(path));
            ownedFiles.Add(path);
        }
    }

    private sealed record IssuerMetadata(string Tenant, string Issuer, int LoopbackPort, string CaFile, string CaSha256,
        string LoginFile, string TotpFile, string IntrospectionFile);
}
