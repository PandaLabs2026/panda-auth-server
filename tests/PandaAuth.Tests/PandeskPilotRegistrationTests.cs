using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public sealed class PandeskPilotRegistrationTests
{
    private const string Issuer = "https://t0000-auth.pandacloud.cc/";
    private const string ClientId = "pandesk-t0000-registration-test";
    private const string Secret = "synthetic-pandesk-introspection-secret-for-test";
    private const string Argument = "--register-pandesk-t0000-only";

    [Fact]
    public async Task CommandRejectsWrongIssuerAndMixedArgumentsBeforeConnecting()
    {
        var configuration = Settings("not a connection string");
        var environment = new HostingEnvironment { EnvironmentName = Environments.Production };
        using var output = new StringWriter();
        Assert.True(PandeskPilotRegistrationCommand.IsRequested([Argument, "--migrate"]));
        Assert.Equal(2, await PandeskPilotRegistrationCommand.RunAsync([Argument, "--migrate"], configuration, environment, output));
        Assert.Contains("command_invalid", output.ToString());
        configuration["Auth:Issuer"] = "https://t1234-auth.pandacloud.cc/";
        Assert.Equal(2, await PandeskPilotRegistrationCommand.RunAsync([Argument], configuration, environment, output));
        Assert.Contains("pandesk_registration_input_invalid", output.ToString());
        Assert.DoesNotContain(Secret, output.ToString());
    }

    [PostgresFact]
    public async Task CreatesOnlyPilotPermissionsAndAllowsConcurrentRepeat()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        var reports = await Task.WhenAll(RegisterAsync(fixture), RegisterAsync(fixture));
        Assert.All(reports, report =>
        {
            Assert.Equal(0, report.ExitCode);
            Assert.Contains("pandesk-t0000-registration-only-v1", report.Output);
            Assert.DoesNotContain(Secret, report.Output);
        });

        using var scope = fixture.Host.Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var desktop = Assert.IsAssignableFrom<object>(await apps.FindByClientIdAsync(ClientId));
        Assert.True(await apps.HasClientTypeAsync(desktop, ClientTypes.Public));
        Assert.Equal(new[] { Issuer + "connect/native/callback" }, await apps.GetRedirectUrisAsync(desktop));
        Assert.Equal(new[] { Requirements.Features.ProofKeyForCodeExchange }, await apps.GetRequirementsAsync(desktop));
        Assert.Equal(new[]
        {
            Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.Endpoints.Revocation,
            Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code,
            Permissions.Prefixes.Scope + PandeskCustomerRead.Scope,
        }.Order(StringComparer.Ordinal), (await apps.GetPermissionsAsync(desktop)).Order(StringComparer.Ordinal));

        var introspector = Assert.IsAssignableFrom<object>(await apps.FindByClientIdAsync(PandeskCustomerRead.IntrospectionClientId));
        Assert.True(await apps.HasClientTypeAsync(introspector, ClientTypes.Confidential));
        Assert.Equal(new[] { Permissions.Endpoints.Introspection }, await apps.GetPermissionsAsync(introspector));
        Assert.True(await apps.ValidateClientSecretAsync(introspector, Secret));

        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var readScope = Assert.IsAssignableFrom<object>(await scopes.FindByNameAsync(PandeskCustomerRead.Scope));
        Assert.Equal(new[] { PandeskCustomerRead.Audience, PandeskCustomerRead.IntrospectionAudience }.Order(StringComparer.Ordinal),
            (await scopes.GetResourcesAsync(readScope)).Order(StringComparer.Ordinal));
    }

    [PostgresFact]
    public async Task DifferentExistingSecretRollsBackNewScopeAndDesktop()
    {
        const string existingSecret = Secret + "-existing";
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        using var scope = fixture.Host.Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await apps.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = PandeskCustomerRead.IntrospectionClientId,
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            ClientSecret = existingSecret,
            Permissions = { Permissions.Endpoints.Introspection },
        });

        var result = await RegisterAsync(fixture);
        Assert.Equal(2, result.ExitCode);
        Assert.Contains("pandesk_registration_conflict", result.Output);
        Assert.DoesNotContain(Secret, result.Output);

        using var verify = fixture.Host.Services.CreateScope();
        var finalApps = verify.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = verify.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        Assert.Null(await scopes.FindByNameAsync(PandeskCustomerRead.Scope));
        Assert.Null(await finalApps.FindByClientIdAsync(ClientId));
        var introspector = Assert.IsAssignableFrom<object>(await finalApps.FindByClientIdAsync(PandeskCustomerRead.IntrospectionClientId));
        Assert.True(await finalApps.ValidateClientSecretAsync(introspector, existingSecret));
    }

    [PostgresFact]
    public async Task Resource_registration_creates_only_the_separate_client_and_scope()
    {
        const string resourceArgument = "--register-native-resource-only";
        const string resourceClient = "dedicated-native-registration-fixture";
        const string resourceScope = "fixture.native.api";
        const string resource = "Auth:NativeLogin:ResourceAccess:";
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        var original = await RegisterAsync(fixture);
        Assert.Equal(0, original.ExitCode);
        var configuration = Settings(fixture.ConnectionString);
        configuration[resource + "ClientId"] = resourceClient;
        configuration[resource + "Scope"] = resourceScope;
        configuration[resource + "Enabled"] = "false";
        configuration[resource + "Revision"] = Guid.NewGuid().ToString("D");
        configuration[resource + "Audiences:0"] = PandeskCustomerRead.Audience;
        configuration[resource + "Audiences:1"] = PandeskCustomerRead.IntrospectionAudience;
        var environment = fixture.Host.Services.GetRequiredService<IHostEnvironment>();
        using var output = new StringWriter();
        Assert.Equal(0, await PandeskPilotRegistrationCommand.RunAsync([resourceArgument], configuration, environment, output));
        Assert.Equal(0, await PandeskPilotRegistrationCommand.RunAsync([resourceArgument], configuration, environment, output));

        using var scope = fixture.Host.Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var resourceApp = Assert.IsAssignableFrom<object>(await apps.FindByClientIdAsync(resourceClient));
        var reader = Assert.IsAssignableFrom<object>(await apps.FindByClientIdAsync(ClientId));
        Assert.True(await apps.HasClientTypeAsync(resourceApp, ClientTypes.Public));
        Assert.True(await apps.HasRequirementAsync(resourceApp, Requirements.Features.ProofKeyForCodeExchange));
        Assert.True(await apps.HasPermissionAsync(resourceApp, Permissions.Prefixes.Scope + resourceScope));
        Assert.False(await apps.HasPermissionAsync(resourceApp, Permissions.Prefixes.Scope + PandeskCustomerRead.Scope));
        Assert.False(await apps.HasPermissionAsync(reader, Permissions.Prefixes.Scope + resourceScope));

        configuration[resource + "Audiences:0"] = "conflicting-audience";
        Assert.Equal(2, await PandeskPilotRegistrationCommand.RunAsync([resourceArgument], configuration, environment, output));
        Assert.Contains("pandesk_registration_conflict", output.ToString());
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var registered = Assert.IsAssignableFrom<object>(await scopes.FindByNameAsync(resourceScope));
        Assert.Contains(PandeskCustomerRead.Audience, await scopes.GetResourcesAsync(registered));
        Assert.DoesNotContain(Secret, output.ToString());
    }

    private static IConfiguration Settings(string connection) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:Issuer"] = Issuer,
            ["ConnectionStrings:Migration"] = connection,
            ["Auth:NativeLogin:ClientId"] = ClientId,
            ["Auth:NativeLogin:T0000Pilot:IntrospectionClientSecret"] = Secret,
        })
        .Build();

    private static async Task<(int ExitCode, string Output)> RegisterAsync(SecurityProtocolFixture fixture)
    {
        using var output = new StringWriter();
        var environment = fixture.Host.Services.GetRequiredService<IHostEnvironment>();
        var code = await PandeskPilotRegistrationCommand.RunAsync([Argument], Settings(fixture.ConnectionString), environment, output);
        return (code, output.ToString());
    }
}
