using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Configuration;

public static class ProfileMeRegistrationCommand
{
    public static bool IsRequested(string[] args) => args.Any(value => value.StartsWith("--register-profile-me", StringComparison.Ordinal));
    public const string Argument = "--register-profile-me-only";
    public const string ApexCallbacksArgument = "--register-profile-me-apex-callbacks";
    public static async Task<int> RunAsync(string[] args, IConfiguration configuration, IHostEnvironment environment, TextWriter output)
    {
        var apexCallbacks = args is [ApexCallbacksArgument];
        if (!apexCallbacks && args is not [Argument])
        {
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new("command", "command_invalid")]));
            return 2;
        }
        var options = configuration.GetSection("Profile").Get<ProfileOptions>() ?? new ProfileOptions();
        if (apexCallbacks && configuration["Auth:Issuer"] != ProfileMeRegistration.ApexIssuer.AbsoluteUri)
        {
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new("Auth:Issuer", "me_apex_issuer_invalid")]));
            return 2;
        }
        if (!apexCallbacks && (!options.Enabled || !options.MeClientEnabled || !options.AllowedClients.Contains(FirstPartyClients.MeWeb, StringComparer.Ordinal)))
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
            if (apexCallbacks)
                await ProfileMeRegistration.ApplyApexCallbacksAsync(scope.ServiceProvider);
            else
                await ProfileMeRegistration.ApplyAsync(scope.ServiceProvider, options);
            OperationalCommand.Write(output, new { Schema = 1, Valid = true, Operation = apexCallbacks
                ? "profile-me-apex-callbacks-v1" : "profile-me-registration-only-v1" });
            return 0;
        }
        catch (Exception)
        {
            // One-off operational boundary: never print connection, SQL, provider or secret details.
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new("Profile",
                apexCallbacks ? "profile_me_apex_callbacks_failed" : "profile_me_registration_failed")]));
            return 2;
        }
    }
}
