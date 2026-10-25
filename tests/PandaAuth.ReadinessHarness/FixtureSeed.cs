using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.ReadinessHarness;

public static class FixtureSeed
{
    public static async Task<object> RunAsync(LoadRequest settings)
    {
        settings.Validate();
        var connection = new NpgsqlConnectionStringBuilder(settings.MigrationConnection);
        var isolatedContainer = OperatingSystem.IsLinux() && File.Exists("/.dockerenv") &&
            Environment.GetEnvironmentVariable("PANDA_AUTH_R1_ISOLATED_RUN") == settings.RunId;
        if (connection.Host != "127.0.0.1" || (connection.Port < 20000 && !(connection.Port == 5432 && isolatedContainer)) ||
            connection.Database != "panda_r1_" + settings.RunId || connection.Username != "panda_r1_" + settings.RunId[..16] + "_owner")
            throw new InvalidOperationException("readiness_database_admission_failed");
        var services = new ServiceCollection().AddLogging();
        services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(connection.ConnectionString).UseOpenIddict());
        services.AddUserStore();
        services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var migrations = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        var upgraded = migrations.Contains(PandaAuth.Server.Configuration.OperationalCommand.SigningMigration);
        if (settings.LegacySchema ? upgraded || !migrations.Contains("20261019121648_AddSessionRevocations") : !upgraded)
            throw new InvalidOperationException("readiness_requires_independent_migration");
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        for (var index = 0; index < settings.Concurrency; index++)
        {
            var name = settings.UserName(index);
            if (await users.FindByNameAsync(name) is not null) continue;
            var user = new PandaUser { UserName = name, Email = name + "@example.invalid", EmailConfirmed = true };
            if (!(await users.CreateAsync(user, settings.Password)).Succeeded) throw new InvalidOperationException("readiness_user_seed_failed");
        }
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await applications.FindByClientIdAsync(settings.ClientId) is not null)
            throw new InvalidOperationException("readiness_client_already_seeded");
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = settings.ClientId, ClientSecret = settings.ClientSecret, ClientType = ClientTypes.Confidential, ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri(settings.RedirectUri) },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken, Permissions.ResponseTypes.Code,
                Permissions.Scopes.Profile, Permissions.Prefixes.Scope + Scopes.OfflineAccess }
        });
        if (settings.RecoveryScenario)
        {
            var administrator = await users.FindByNameAsync(settings.AdminUserName) ?? throw new InvalidOperationException("readiness_recovery_admin_missing");
            if (await db.TotpFactors.AnyAsync(item => item.UserId == administrator.Id)) throw new InvalidOperationException("readiness_recovery_factor_exists");
            var factor = new MfaTotpFactor { Id = Guid.NewGuid(), UserId = administrator.Id, ConfirmedAt = DateTimeOffset.UtcNow };
            var encrypted = new TotpSecretProtector(Convert.FromBase64String(settings.RecoveryTotpKey), "v1")
                .Protect(administrator.Id, factor.Id, RecoveryCrypto.SyntheticTotpSecret(settings.RunId));
            factor.KeyVersion = encrypted.KeyVersion; factor.Nonce = encrypted.Nonce; factor.Ciphertext = encrypted.Ciphertext; factor.Tag = encrypted.Tag;
            db.TotpFactors.Add(factor);
            administrator.TwoFactorEnabled = true;
            await db.SaveChangesAsync();
            await FixtureRecoveryState.PopulateAsync(db, users, scope.ServiceProvider.GetRequiredService<LoginSessionService>(), settings, administrator);
        }
        return new { schema = 1, valid = true, settings.RunId, users = settings.Concurrency };
    }
}
