using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Configuration;

internal static class PandeskPilotRegistrationCommand
{
    private const string Prefix = "--register-pandesk-t0000";
    private const string Argument = Prefix + "-only";

    internal static bool IsRequested(string[] args) =>
        args.Any(arg => arg.StartsWith(Prefix, StringComparison.Ordinal));

    internal static async Task<int> RunAsync(string[] args, IConfiguration configuration,
        IHostEnvironment environment, TextWriter output)
    {
        if (args is not [Argument]) return Reject(output, "command", "command_invalid");

        var clientId = configuration["Auth:NativeLogin:ClientId"];
        var secret = configuration["Auth:NativeLogin:T0000Pilot:IntrospectionClientSecret"];
        if (configuration["Auth:Issuer"] != NativeLoginRoute.PilotIssuer
            || clientId is not { Length: > 0 and <= BusinessInputLimits.ClientId }
            || clientId.Any(character => char.IsWhiteSpace(character) || char.IsControl(character))
            || clientId == PandeskCustomerRead.IntrospectionClientId
            || secret is not { Length: >= 32 } || string.IsNullOrWhiteSpace(secret))
            return Reject(output, "Auth:NativeLogin", "pandesk_registration_input_invalid");

        var report = StartupConfiguration.Validate(configuration, environment, migrate: true);
        if (!report.Valid)
        {
            OperationalCommand.Write(output, report);
            return 2;
        }

        try
        {
            var connection = configuration.GetConnectionString("Migration")!;
            if (environment.IsProduction() && new NpgsqlConnectionStringBuilder(connection) is not
                { Host: "pandalabs-postgres", Port: 5432, Database: "panda_auth_t0000", Username: "panda_auth_t0000_migrator" })
                return Reject(output, "ConnectionStrings:Migration", "pandesk_registration_provider_invalid");

            var services = new ServiceCollection();
            services.AddLogging(logging => logging.ClearProviders());
            services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(connection).UseOpenIddict());
            services.AddOpenIddict().AddCore(core =>
            {
                core.DisableEntityCaching();
                core.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>();
            });
            await using var provider = services.BuildServiceProvider();
            await using var lease = await DatabaseLease.AcquireAsync(connection);
            await using var scope = provider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            if ((await db.Database.GetPendingMigrationsAsync()).Any())
                return Reject(output, "ConnectionStrings:Migration", "pandesk_registration_schema_not_ready");

            if (!await RegisterAsync(scope.ServiceProvider, db, clientId, secret))
                return Reject(output, "Auth:NativeLogin", "pandesk_registration_conflict");

            OperationalCommand.Write(output, new { Schema = 1, Valid = true, Operation = "pandesk-t0000-registration-only-v1", ClientId = clientId });
            return 0;
        }
        catch (Exception)
        {
            // Do not echo provider errors, database credentials, or client secrets.
            return Reject(output, "Auth:NativeLogin", "pandesk_registration_failed");
        }
    }

    private static async Task<bool> RegisterAsync(IServiceProvider services, PandaAuthDbContext db,
        string clientId, string secret)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var scopes = services.GetRequiredService<IOpenIddictScopeManager>();
        var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
        var readScope = new OpenIddictScopeDescriptor
        {
            Name = PandeskCustomerRead.Scope,
            Resources = { PandeskCustomerRead.Audience, PandeskCustomerRead.IntrospectionAudience },
        };
        var existingScope = await scopes.FindByNameAsync(readScope.Name);
        if (existingScope is null)
            await scopes.CreateAsync(readScope);
        else if (!readScope.Resources.SetEquals(await scopes.GetResourcesAsync(existingScope)))
            return false;

        var desktop = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri(new Uri(NativeLoginRoute.PilotIssuer), NativeLoginRoute.Callback) },
            Permissions =
            {
                Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + PandeskCustomerRead.Scope,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        };
        var introspector = new OpenIddictApplicationDescriptor
        {
            ClientId = PandeskCustomerRead.IntrospectionClientId,
            ClientType = ClientTypes.Confidential,
            ClientSecret = secret,
            ConsentType = ConsentTypes.Implicit,
            Permissions = { Permissions.Endpoints.Introspection },
        };
        if (!await CreateOrMatchAsync(applications, desktop) || !await CreateOrMatchAsync(applications, introspector))
            return false;

        await transaction.CommitAsync();
        return true;
    }

    private static async Task<bool> CreateOrMatchAsync(IOpenIddictApplicationManager applications,
        OpenIddictApplicationDescriptor expected)
    {
        var existing = await applications.FindByClientIdAsync(expected.ClientId!);
        if (existing is null)
        {
            await applications.CreateAsync(expected);
            return true;
        }

        var actual = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(actual, existing);
        return actual.ApplicationType == expected.ApplicationType && actual.ClientType == expected.ClientType
            && actual.ConsentType == expected.ConsentType && actual.JsonWebKeySet is null
            && actual.Properties.Count == 0 && actual.Settings.Count == 0
            && (await applications.GetRedirectUrisAsync(existing)).ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected.RedirectUris.Select(uri => uri.AbsoluteUri))
            && actual.PostLogoutRedirectUris.Count == 0
            && actual.Permissions.SetEquals(expected.Permissions) && actual.Requirements.SetEquals(expected.Requirements)
            && (expected.ClientSecret is null
                ? string.IsNullOrEmpty(actual.ClientSecret)
                : await applications.ValidateClientSecretAsync(existing, expected.ClientSecret));
    }

    private static int Reject(TextWriter output, string key, string code)
    {
        OperationalCommand.Write(output, new ConfigurationReport(1, false, [new(key, code)]));
        return 2;
    }
}
