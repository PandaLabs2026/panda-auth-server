using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.ReadinessHarness;

public static class FixtureSeed
{
    public static async Task<object> RunAsync(LoadRequest settings)
    {
        settings.Validate();
        var connection = new NpgsqlConnectionStringBuilder(settings.MigrationConnection);
        if (connection.Host != "127.0.0.1" || connection.Port < 20000 ||
            !Regex.IsMatch(connection.Database ?? "", "^panda_r1_[0-9a-f]{32}$") ||
            !Regex.IsMatch(connection.Username ?? "", "^panda_r1_[0-9a-f]{16}_owner$"))
            throw new InvalidOperationException("readiness_database_admission_failed");
        var services = new ServiceCollection().AddLogging();
        services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(connection.ConnectionString).UseOpenIddict());
        services.AddUserStore();
        services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        if (!(await db.Database.GetAppliedMigrationsAsync()).Contains(PandaAuth.Server.Configuration.OperationalCommand.SigningMigration))
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
        return new { schema = 1, valid = true, settings.RunId, users = settings.Concurrency };
    }
}
