using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public class DbSeederTests
{
    [Fact]
    public async Task SeedDisabled_DoesNotResolveSeedDependencies()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Options.Create(new AuthOptions
        {
            Seed = new SeedOptions { Enabled = false },
        }));

        await DbSeeder.SeedAsync(services.BuildServiceProvider());
    }
}
