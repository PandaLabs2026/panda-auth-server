using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public class ProfileMeRegistrationCommandTests
{
    [PostgresFact]
    public async Task ExactCommandRegistersExistingMeWithoutStartingRuntimeOrExposingConfiguration()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = FirstPartyClients.MeWeb, ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ClientSecret = "synthetic-command-test-only",
            Permissions = { OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddictConstants.Permissions.GrantTypes.RefreshToken },
        });
        var connection = db.Database.GetConnectionString()!;
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Migration"] = connection, ["Auth:Issuer"] = "https://fixture.invalid/",
            ["Auth:Seed:Enabled"] = "false", ["Profile:Enabled"] = "true", ["Profile:MeClientEnabled"] = "true",
            ["Profile:AllowedClients:0"] = FirstPartyClients.MeWeb,
        }).Build();
        var environment = new HostApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Development, DisableDefaults = true }).Environment;
        using var output = new StringWriter();
        Assert.Equal(0, await ProfileMeRegistrationCommand.RunAsync([ProfileMeRegistrationCommand.Argument], configuration, environment, output));
        var client = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync();
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Scope + ProfileScopes.Read, client.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Scope + ProfileScopes.Write, client.Permissions);
        Assert.DoesNotContain(connection, output.ToString());
        Assert.DoesNotContain("synthetic-command-test-only", output.ToString());
    }

    [Theory]
    [InlineData("--register-profile-me-only", "--migrate")]
    [InlineData("--register-profile-me-unknown")]
    public async Task MalformedCommandCannotFallThroughIntoRuntime(params string[] arguments)
    {
        using var output = new StringWriter();
        var environment = new HostApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Development, DisableDefaults = true }).Environment;
        Assert.True(ProfileMeRegistrationCommand.IsRequested(arguments));
        Assert.Equal(2, await ProfileMeRegistrationCommand.RunAsync(arguments, new ConfigurationBuilder().Build(), environment, output));
        Assert.Contains("command_invalid", output.ToString());
    }
}
