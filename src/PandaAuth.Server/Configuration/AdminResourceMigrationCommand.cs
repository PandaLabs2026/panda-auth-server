using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Configuration;

/// <summary>One-off activation migrator; never constructs the runtime/key-manager host.</summary>
public static class AdminResourceMigrationCommand
{
    public const string Argument = "--migrate-admin-resource-only";
    public const string Capability = "admin-resource-only-v1";

    public static bool IsRequested(string[] arguments) => arguments.Any(value =>
        value.StartsWith("--migrate-admin-resource", StringComparison.Ordinal));

    public static async Task<int> RunAsync(string[] arguments, IConfiguration configuration, IHostEnvironment environment, TextWriter output)
    {
        if (arguments is not [Argument])
        {
            OperationalCommand.Write(output, new ConfigurationReport(1, false, [new("command", "command_invalid")]));
            return 2;
        }
        var report = StartupConfiguration.Validate(configuration, environment, migrate: true);
        if (!report.Valid)
        {
            OperationalCommand.Write(output, report);
            return 2;
        }
        try
        {
            var connection = configuration.GetConnectionString("Migration")!;
            var services = new ServiceCollection();
            services.AddLogging(logging => logging.ClearProviders());
            services.AddDbContext<PandaAuthDbContext>(options => options.UseNpgsql(connection).UseOpenIddict());
            services.AddOpenIddict().AddCore(options =>
            {
                options.DisableEntityCaching();
                options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>();
            });
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            await using var lease = await DatabaseLease.AcquireAsync(connection);
            // Reject missing/incompatible existing registrations before any DDL.
            await AdminResourceActivation.ValidateSourceAsync(scope.ServiceProvider);
            var original = await ActivationPreservation.CaptureAsync(connection);
            await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.MigrateAsync();
            await AdminResourceActivation.ApplyAsync(scope.ServiceProvider);
            ActivationPreservation.RequireUnchanged(original, await ActivationPreservation.CaptureAsync(connection, original));
            OperationalCommand.Write(output, new { Schema = 1, Valid = true, Operation = Capability });
            return 0;
        }
        catch (Exception)
        {
            // Operational boundary: no provider, SQL, credential or exception text.
            OperationalCommand.Write(output, new ConfigurationReport(1, false,
                [new("Migration", "admin_resource_migration_failed")]));
            return 2;
        }
    }
}
