using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class StartupConfigurationProcessTests
{
    [Fact]
    public async Task ValidRuntimeValidation_DoesNotConnectOrGenerateKeys()
    {
        await using var fixture = new ProcessFixture();
        var result = await fixture.RunAsync(["--validate-config", "--mode", "runtime"]);
        Assert.Equal(0, result.Code);
        using var json = JsonDocument.Parse(result.Output);
        Assert.True(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.Empty(Directory.GetFiles(fixture.Root, "*.xml", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData("Auth__DataProtectionKeyPath", "", "dp_required")]
    [InlineData("Auth__CookieSecure", "SameAsRequest", "secure_cookie_required")]
    [InlineData("Auth__CookieSecure", "Never", "auth_binding_invalid")]
    [InlineData("Auth__Issuer", "http://fixture.invalid/", "issuer_https_required")]
    [InlineData("Auth__Issuer", "https://user:sentinel-do-not-disclose@fixture.invalid/", "issuer_invalid")]
    [InlineData("Auth__Mfa__TotpEncryptionKey", "sentinel-do-not-disclose", "mfa_invalid")]
    [InlineData("Auth__Keys__ValidityDays", "91", "signing_window_invalid")]
    [InlineData("Email__ApiKey", "", "email_invalid")]
    [InlineData("PANDA_AUTH_TRUSTED_PROXY", "100.64.0.0/16", "proxy_invalid")]
    public async Task RuntimeValidation_RejectsBeforeDatabaseAccess_WithRedactedErrors(string key, string value, string code)
    {
        await using var fixture = new ProcessFixture();
        fixture.Environment[key] = value;
        var result = await fixture.RunAsync(["--validate-config", "--mode", "runtime"]);
        Assert.Equal(2, result.Code);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.Contains(json.RootElement.GetProperty("errors").EnumerateArray(), error => error.GetProperty("code").GetString() == code);
        Assert.DoesNotContain("sentinel-do-not-disclose", result.Output + result.Error);
    }

    [Fact]
    public async Task ActualStartup_RejectsMissingDp_BeforeConnecting()
    {
        await using var fixture = new ProcessFixture();
        fixture.Environment["Auth__DataProtectionKeyPath"] = "";
        var result = await fixture.RunAsync([]);
        Assert.Equal(2, result.Code);
        using var json = JsonDocument.Parse(result.Error);
        Assert.Contains(json.RootElement.GetProperty("errors").EnumerateArray(), error => error.GetProperty("code").GetString() == "dp_required");
        Assert.DoesNotContain("Npgsql", result.Error + result.Output);
    }

    [Fact]
    public async Task MigrateValidation_DoesNotRequireRuntimeDpCookieOrEmail()
    {
        await using var fixture = new ProcessFixture();
        fixture.Environment["Auth__DataProtectionKeyPath"] = "";
        fixture.Environment["Auth__CookieSecure"] = "SameAsRequest";
        fixture.Environment["Email__ApiKey"] = "";
        var result = await fixture.RunAsync(["--validate-config", "--mode", "migrate"]);
        Assert.Equal(0, result.Code);
    }

    [Theory]
    [InlineData("--validate-config")]
    [InlineData("--validate-config", "--mode", "other")]
    [InlineData("--validate-config", "--mode", "runtime", "--migrate")]
    [InlineData("--security-state", "--migrate")]
    public async Task InvalidCommandShape_DoesNotFallIntoWebStartup(params string[] arguments)
    {
        await using var fixture = new ProcessFixture();
        var result = await fixture.RunAsync(arguments);
        Assert.Equal(2, result.Code);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task DevelopmentLoopback_CanValidateWithoutProductionMaterials()
    {
        await using var fixture = new ProcessFixture();
        fixture.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        fixture.Environment["DOTNET_ENVIRONMENT"] = "Development";
        fixture.Environment["Auth__Issuer"] = "http://localhost:12999/";
        fixture.Environment["Auth__DataProtectionKeyPath"] = "";
        fixture.Environment["Auth__CookieSecure"] = "SameAsRequest";
        fixture.Environment["Auth__Mfa__TotpEncryptionKey"] = "";
        fixture.Environment["Email__ApiKey"] = "";
        var result = await fixture.RunAsync(["--validate-config", "--mode", "runtime"]);
        Assert.Equal(0, result.Code);
    }

    [PostgresFact]
    public async Task SecurityState_ReportsActualSchema_WithoutSeedingOrCreatingKeys()
    {
        await using var database = await AuthQualityPostgresFixture.CreateAsync();
        using var scope = database.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        await using var process = new ProcessFixture();
        process.Environment["ConnectionStrings__Migration"] = db.Database.GetConnectionString()!;
        var current = await process.RunAsync(["--security-state"]);
        Assert.Equal(0, current.Code);
        using var upgraded = JsonDocument.Parse(current.Output);
        Assert.Equal("online-signing-v1", upgraded.RootElement.GetProperty("compatibility").GetString());
        Assert.Empty(await db.SigningKeys.ToListAsync());
        Assert.Empty(await db.Users.ToListAsync());
        var migrations = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        Assert.Equal(OperationalCommand.SigningMigration, migrations[^1]);
        await db.GetService<IMigrator>().MigrateAsync(migrations[^2]);
        var legacy = await process.RunAsync(["--security-state"]);
        Assert.Equal(0, legacy.Code);
        using var old = JsonDocument.Parse(legacy.Output);
        Assert.Equal("legacy", old.RootElement.GetProperty("compatibility").GetString());
        Assert.Equal(upgraded.RootElement.GetProperty("databaseFingerprint").GetString(), old.RootElement.GetProperty("databaseFingerprint").GetString());
        Assert.Equal(migrations.Length - 1, (await db.Database.GetAppliedMigrationsAsync()).Count());
    }

    [PostgresFact]
    public async Task SecurityState_PartialOrConflictingSchema_IsUnknownRatherThanLegacy()
    {
        await using var database = await AuthQualityPostgresFixture.CreateAsync();
        using var scope = database.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        await db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM \"__EFMigrationsHistory\" WHERE \"MigrationId\" = {OperationalCommand.SigningMigration}");
        await using var process = new ProcessFixture();
        process.Environment["ConnectionStrings__Migration"] = db.Database.GetConnectionString()!;
        var result = await process.RunAsync(["--security-state"]);
        Assert.Equal(2, result.Code);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.DoesNotContain("Npgsql", result.Error + result.Output);
    }

    [Theory]
    [InlineData("--migrate-admin-resource-only", "--migrate")]
    [InlineData("--migrate-admin-resource-only=1")]
    public async Task ResourceMigration_InvalidShapeFailsClosedBeforeDatabaseAccess(params string[] arguments)
    {
        await using var process = new ProcessFixture();
        var result = await process.RunAsync(arguments);
        Assert.Equal(2, result.Code);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.DoesNotContain("Npgsql", result.Error + result.Output);
    }

    [PostgresFact]
    public async Task ResourceMigration_UpgradesLegacySchemaWithoutFullSeedingOrKeyInitialization()
    {
        await using var database = await AuthQualityPostgresFixture.CreateAsync();
        using var scope = database.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = FirstPartyClients.AdminWeb, ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ClientSecret = "synthetic-original-secret",
            Permissions = { OpenIddictConstants.Permissions.Endpoints.Authorization, OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddictConstants.Permissions.ResponseTypes.Code },
            RedirectUris = { new Uri("https://fixture.invalid/original-callback") },
        });
        var original = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync();
        db.Users.Add(new PandaUser { Id = Guid.NewGuid().ToString(), UserName = "fixture-existing", PasswordHash = "unchanged", SecurityStamp = "unchanged" });
        await db.SaveChangesAsync();
        var migrations = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        await db.GetService<IMigrator>().MigrateAsync(migrations[^2]);
        await using var process = new ProcessFixture();
        process.Environment["ConnectionStrings__Migration"] = db.Database.GetConnectionString()!;
        process.Environment["Auth__Seed__Admin__Email"] = "must-not-create@example.invalid";
        process.Environment["Auth__Seed__Admin__Password"] = "synthetic-must-not-seed-password";
        process.Environment["Auth__Seed__AdminWeb__ClientSecret"] = "synthetic-must-not-reconcile-secret";
        var result = await process.RunAsync(["--migrate-admin-resource-only"]);
        Assert.Equal(0, result.Code);
        using var report = JsonDocument.Parse(result.Output);
        Assert.True(report.RootElement.GetProperty("valid").GetBoolean());
        var after = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync();
        Assert.Equal(original.ClientSecret, after.ClientSecret);
        Assert.Equal(original.RedirectUris, after.RedirectUris);
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope, after.Permissions ?? "");
        Assert.Equal(1, await db.Users.CountAsync());
        Assert.Empty(await db.SigningKeys.ToListAsync());
        Assert.Empty(Directory.GetFiles(process.Root, "*.xml", SearchOption.AllDirectories));
        Assert.Contains(OperationalCommand.SigningMigration, await db.Database.GetAppliedMigrationsAsync());
        Assert.Equal(0, (await process.RunAsync(["--migrate-admin-resource-only"])).Code);
    }

    [PostgresFact]
    public async Task ResourceMigration_MissingExistingAdminClientRejectsBeforeDdl()
    {
        await using var database = await AuthQualityPostgresFixture.CreateAsync();
        using var scope = database.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var migrations = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        await db.GetService<IMigrator>().MigrateAsync(migrations[^2]);
        await using var process = new ProcessFixture();
        process.Environment["ConnectionStrings__Migration"] = db.Database.GetConnectionString()!;
        var result = await process.RunAsync(["--migrate-admin-resource-only"]);
        Assert.Equal(2, result.Code);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.DoesNotContain(OperationalCommand.SigningMigration, await db.Database.GetAppliedMigrationsAsync());
        Assert.Equal(0, await db.Users.CountAsync());
        Assert.Equal(0, await db.SigningKeys.CountAsync());
        Assert.DoesNotContain("Npgsql", result.Output + result.Error);
    }

    private sealed class ProcessFixture : IAsyncDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "panda-r1-config-" + Guid.NewGuid().ToString("N"));
        internal Dictionary<string, string> Environment { get; } = new()
        {
            ["ASPNETCORE_ENVIRONMENT"] = "Production",
            ["DOTNET_ENVIRONMENT"] = "Production",
            ["ConnectionStrings__Default"] = "Host=127.0.0.1;Port=1;Database=panda_r1_config;Username=fixture;Timeout=1",
            ["ConnectionStrings__Migration"] = "Host=127.0.0.1;Port=1;Database=panda_r1_config;Username=fixture;Timeout=1",
            ["Auth__Issuer"] = "https://fixture.invalid/",
            ["Auth__CookieSecure"] = "Always",
            ["Auth__HttpsRequired"] = "false",
            ["Auth__Mfa__TotpEncryptionKey"] = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()),
            ["Email__ApiKey"] = "synthetic-only",
            ["Email__FromAddress"] = "fixture@example.invalid",
            ["PANDA_AUTH_TENANT_NETWORK_MODE"] = "bridge",
            ["PANDA_AUTH_TRUSTED_PROXY"] = "100.64.0.1"
        };

        internal ProcessFixture()
        {
            Directory.CreateDirectory(Root);
            Environment["Auth__DataProtectionKeyPath"] = Root;
        }

        internal async Task<(int Code, string Output, string Error)> RunAsync(string[] arguments)
        {
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = Root, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (var name in start.Environment.Keys.Where(name => name.StartsWith("Auth__", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Email__", StringComparison.OrdinalIgnoreCase) || name.StartsWith("ConnectionStrings__", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("PANDA_AUTH_", StringComparison.OrdinalIgnoreCase)).ToArray()) start.Environment.Remove(name);
            foreach (var (name, value) in Environment) start.Environment[name] = value;
            foreach (var argument in new[] { "exec", "--runtimeconfig", Path.Combine(AppContext.BaseDirectory, "PandaAuth.Tests.runtimeconfig.json"),
                "--depsfile", Path.Combine(AppContext.BaseDirectory, "PandaAuth.Tests.deps.json"), typeof(AuthOptions).Assembly.Location }.Concat(arguments))
                start.ArgumentList.Add(argument);
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25)); }
            finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
            return (process.ExitCode, await output, await error);
        }

        public ValueTask DisposeAsync() { Directory.Delete(Root, recursive: true); return ValueTask.CompletedTask; }
    }
}
