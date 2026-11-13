using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;
namespace PandaAuth.Server.Configuration;

/// <summary>显式定向登记，不启动Web、不迁移Schema或运行其它seed。</summary>
public static class CloudConfigRegistrationCommand
{
    public const string Argument="--register-cloud-config-only";
    public static bool IsRequested(string[] args)=>args.Any(value=>value.StartsWith("--register-cloud-config",StringComparison.Ordinal));
    public static async Task<int> RunAsync(string[] args,IConfiguration configuration,IHostEnvironment environment,TextWriter output)
    {
        if(args is not [Argument])
        {OperationalCommand.Write(output,new ConfigurationReport(1,false,[new("command","command_invalid")]));return 2;}
        try
        {
            var options=configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>()??new();
            if(!options.Seed.Enabled||!options.Seed.CloudConfig.Enabled||!options.Seed.CloudConsoleWeb.Enabled||options.Seed.CloudConfig.FleetReadEnabled)
            {OperationalCommand.Write(output,new ConfigurationReport(1,false,[new("Auth:Seed:CloudConfig","cloud_config_registration_closed")]));return 2;}
            var report=StartupConfiguration.Validate(configuration,environment,migrate:true);
            if(!report.Valid){OperationalCommand.Write(output,report);return 2;}
            var connection=configuration.GetConnectionString("Migration")!;
            var services=new ServiceCollection();services.AddLogging(logging=>logging.ClearProviders());
            services.AddDbContext<PandaAuthDbContext>(db=>db.UseNpgsql(connection).UseOpenIddict());
            services.AddOpenIddict().AddCore(core=>{core.DisableEntityCaching();core.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>();});
            await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
            await using var lease=await DatabaseLease.AcquireAsync(connection);
            if((await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.GetPendingMigrationsAsync()).Any())
                throw new InvalidOperationException("cloud_config_schema_not_ready");
            await CloudConfigRegistration.ApplyOnlyAsync(scope.ServiceProvider,options);
            OperationalCommand.Write(output,new {Schema=1,Valid=true,Operation="cloud-config-registration-only-v1"});return 0;
        }
        catch(Exception)
        {
            // 连接、SQL、secret和底层异常均不进入公开回执。
            OperationalCommand.Write(output,new ConfigurationReport(1,false,[new("Auth:Seed:CloudConfig","cloud_config_registration_failed")]));return 2;
        }
    }
}
