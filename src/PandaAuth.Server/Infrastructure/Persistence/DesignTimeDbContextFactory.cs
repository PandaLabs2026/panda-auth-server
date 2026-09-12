using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using OpenIddict.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>供 dotnet-ef 离线生成迁移（无需运行中的数据库）。</summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<PandaAuthDbContext>
{
    public PandaAuthDbContext CreateDbContext(string[] args)
    {
        var connectionString = ResolveConnectionString();
        var options = new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(connectionString)
            .UseOpenIddict()
            .Options;
        return new PandaAuthDbContext(options);
    }

    private static string ResolveConnectionString()
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        return configuration.GetConnectionString("Default")
            ?? "Host=localhost;Port=5432;Database=panda_auth_dev;Username=panda_auth;Password=panda_auth";
    }
}
