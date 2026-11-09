using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
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
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var original = await ActivationPreservation.PrepareAsync(db, connection);
            var appliedCount = (await db.Database.GetAppliedMigrationsAsync()).Count();
            if (original.AddedMigrations is { Count: > 0 })
                await db.GetService<IMigrator>().MigrateAsync(ActivationPreservation.LastReviewedMigration);
            var expectedHistory = db.Database.GetMigrations().Take(appliedCount + (original.AddedMigrations?.Count ?? 0));
            if (!(await db.Database.GetAppliedMigrationsAsync()).SequenceEqual(expectedHistory, StringComparer.Ordinal))
                throw new InvalidOperationException("activation_migration_history_mismatch");
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
