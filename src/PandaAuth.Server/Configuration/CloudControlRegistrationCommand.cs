using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
namespace PandaAuth.Server.Configuration;

/// <summary>Explicit targeted registration; never starts Web, migrates schema or runs general seed.</summary>
public static class CloudControlRegistrationCommand
{
    public const string Argument="--register-cloud-control-only";
    public static bool IsRequested(string[] args)=>args.Any(value=>value.StartsWith("--register-cloud-control",StringComparison.Ordinal));
    public static async Task<int> RunAsync(string[] args,IConfiguration configuration,IHostEnvironment environment,TextWriter output)
    {
        if(args is not [Argument])
        {OperationalCommand.Write(output,new ConfigurationReport(1,false,[new("command","command_invalid")]));return 2;}
        try
        {
            var options=configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>()??new();
            if(!options.CloudControl.Enabled||options.Issuer!=CloudConfigScopes.Issuer)
            {OperationalCommand.Write(output,new ConfigurationReport(1,false,[new("Auth:CloudControl","cloud_control_registration_closed")]));return 2;}
            var report=StartupConfiguration.Validate(configuration,environment,migrate:true);
            if(!report.Valid){OperationalCommand.Write(output,report);return 2;}
            var connection=configuration.GetConnectionString("Migration")!;
            var services=new ServiceCollection();services.AddLogging(logging=>logging.ClearProviders());
            services.AddDbContext<PandaAuthDbContext>(db=>db.UseNpgsql(connection).UseOpenIddict());
            services.AddOpenIddict().AddCore(core=>{core.DisableEntityCaching();core.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>();});
            await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
            await using var lease=await DatabaseLease.AcquireAsync(connection);
            if((await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.GetPendingMigrationsAsync()).Any())
                throw new InvalidOperationException("CLOUD_CONTROL_SCHEMA_NOT_READY");
            await CloudControlRegistration.ApplyOnlyAsync(scope.ServiceProvider,options);
            OperationalCommand.Write(output,new {Schema=1,Valid=true,Operation="cloud-control-registration-only-v1"});return 0;
        }
        catch(Exception)
        {
            OperationalCommand.Write(output,new ConfigurationReport(1,false,[new("Auth:CloudControl","cloud_control_registration_failed")]));return 2;
        }
    }
}
