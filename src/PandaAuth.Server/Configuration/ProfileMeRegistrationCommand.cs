using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Configuration;

public static class ProfileMeRegistrationCommand
{
    public static bool IsRequested(string[] args) => args.Any(value =>
        value.StartsWith("--register-profile-me", StringComparison.Ordinal)
        || value.StartsWith("--register-oasis-apex-", StringComparison.Ordinal));
    public const string Argument = "--register-profile-me-only";
    public const string ApexCallbacksArgument = "--register-profile-me-apex-callbacks";
    public const string OasisApexCallbacksArgument = "--register-oasis-apex-callbacks";
    public static async Task<int> RunAsync(string[] args, IConfiguration configuration, IHostEnvironment environment, TextWriter output)
    {
        var apexClient = args switch
        {
            [ApexCallbacksArgument] => FirstPartyClients.MeWeb,
            [OasisApexCallbacksArgument] => FirstPartyClients.OasisWeb,
            _ => null,
        };
        var oasis = apexClient == FirstPartyClients.OasisWeb;
        if (apexClient is null && args is not [Argument])
        {
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new("command", "command_invalid")]));
            return 2;
        }
        var options = configuration.GetSection("Profile").Get<ProfileOptions>() ?? new ProfileOptions();
        if (apexClient is not null && configuration["Auth:Issuer"] != ProfileMeRegistration.ApexIssuer.AbsoluteUri)
        {
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new("Auth:Issuer", oasis ? "oasis_apex_issuer_invalid" : "me_apex_issuer_invalid")]));
            return 2;
        }
        if (apexClient is null && (!options.Enabled || !options.MeClientEnabled || !options.AllowedClients.Contains(FirstPartyClients.MeWeb, StringComparer.Ordinal)))
        {
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new("Profile", "profile_me_registration_closed")]));
            return 2;
        }
        var report = StartupConfiguration.Validate(configuration, environment, migrate: true);
        if (!report.Valid) { OperationalCommand.Write(output, report); return 2; }
        try
        {
            var connection = configuration.GetConnectionString("Migration")!;
            var services = new ServiceCollection();
            services.AddLogging(logging => logging.ClearProviders());
            services.AddDbContext<PandaAuthDbContext>(db => db.UseNpgsql(connection).UseOpenIddict());
            services.AddOpenIddict().AddCore(core =>
            {
                core.DisableEntityCaching();
                core.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>();
            });
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            await using var lease = await DatabaseLease.AcquireAsync(connection);
            if ((await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.GetPendingMigrationsAsync()).Any())
                throw new InvalidOperationException("profile_schema_not_ready");
            if (apexClient is not null)
                await ProfileMeRegistration.ApplyApexCallbacksAsync(scope.ServiceProvider, apexClient);
            else
                await ProfileMeRegistration.ApplyAsync(scope.ServiceProvider, options);
            var operation = apexClient switch
            {
                FirstPartyClients.MeWeb => "profile-me-apex-callbacks-v1",
                FirstPartyClients.OasisWeb => "oasis-apex-callbacks-v1",
                _ => "profile-me-registration-only-v1",
            };
            OperationalCommand.Write(output, new { Schema = 1, Valid = true, Operation = operation });
            return 0;
        }
        catch (Exception)
        {
            // One-off operational boundary: never print connection, SQL, provider or secret details.
            var code = apexClient switch
            {
                FirstPartyClients.MeWeb => "profile_me_apex_callbacks_failed",
                FirstPartyClients.OasisWeb => "oasis_apex_callbacks_failed",
                _ => "profile_me_registration_failed",
            };
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new(oasis ? FirstPartyClients.OasisWeb : "Profile", code)]));
            return 2;
        }
    }
}
