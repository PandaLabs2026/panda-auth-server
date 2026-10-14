using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;

[assembly: HostingStartup(typeof(PandaMade.ProtocolFixture.ProtocolHostingStartup))]
namespace PandaMade.ProtocolFixture;

// Test-only lifetime override on the actual PandaAuth host, never referenced by the product.
// https://learn.microsoft.com/aspnet/core/fundamentals/host/platform-specific-configuration?view=aspnetcore-10.0
public sealed class ProtocolHostingStartup : IHostingStartup
{
    public void Configure(IWebHostBuilder builder)
    {
        var root = Environment.GetEnvironmentVariable("PANDAMADE_FIXTURE_ROOT") ?? "";
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") != "Development" ||
            !root.StartsWith(Path.Combine(Path.GetTempPath(),"pandamade-business-test")+Path.DirectorySeparatorChar,StringComparison.Ordinal) || !Directory.Exists(root))
            throw new InvalidOperationException("Fixture host is restricted to dedicated development runs.");
        builder.ConfigureServices(services => services.PostConfigureAll<OpenIddictServerOptions>(options =>
            { options.AccessTokenLifetime = TimeSpan.FromSeconds(10); Console.Error.WriteLine("Fixture access lifetime=10s"); }));
    }
}
