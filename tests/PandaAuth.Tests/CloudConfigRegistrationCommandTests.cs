using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace PandaAuth.Tests;
public class CloudConfigRegistrationCommandTests
{
    static IHostEnvironment Environment() => new HostApplicationBuilder(new HostApplicationBuilderSettings {EnvironmentName=Environments.Development,DisableDefaults=true}).Environment;
    static IConfiguration Config(string connection, bool enabled=true, string secret="cloud-config-command-fixture") => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
        ["ConnectionStrings:Migration"]=connection,["Auth:Issuer"]=CloudConfigScopes.Issuer,
        ["Auth:Seed:Enabled"]=enabled.ToString(),["Auth:Seed:CloudConfig:Enabled"]=enabled.ToString(),
        ["Auth:Seed:CloudConfig:ClientSecret"]=secret,["Auth:Seed:CloudConsoleWeb:Enabled"]="true",
    }).Build();
    [Theory]
    [InlineData("--register-cloud-config-only","--migrate")]
    [InlineData("--register-cloud-config-unknown")]
    public async Task MalformedCommandNeverStartsWeb(params string[] args)
    {
        using var output=new StringWriter();Assert.True(CloudConfigRegistrationCommand.IsRequested(args));
        Assert.Equal(2,await CloudConfigRegistrationCommand.RunAsync(args,new ConfigurationBuilder().Build(),Environment(),output));
        Assert.Contains("command_invalid",output.ToString());
    }
    [Fact]
    public async Task DisabledRegistrationRejectsBeforeConnectionAndDoesNotExposeSecrets()
    {
        using var output=new StringWriter();const string sensitive="Host=not-a-database;Username=fixture;Password=must-not-print";
        Assert.Equal(2,await CloudConfigRegistrationCommand.RunAsync([CloudConfigRegistrationCommand.Argument],Config(sensitive,false),Environment(),output));
        Assert.DoesNotContain(sensitive,output.ToString());Assert.Contains("cloud_config_registration_closed",output.ToString());
    }
    [Fact]
    public async Task DedicatedConsoleRoleModeUsesTheSameDisabledRegistrationGuard()
    {
        using var output = new StringWriter();
        const string roleArgument = "--register-cloud-config-console-role-only";
        Assert.True(CloudConfigRegistrationCommand.IsRequested([roleArgument]));
        Assert.Equal(2, await CloudConfigRegistrationCommand.RunAsync([roleArgument], Config("invalid", false), Environment(), output));
        Assert.Contains("cloud_config_registration_closed", output.ToString());
    }

    [PostgresFact]
    public async Task DedicatedConsoleRoleModeRegistersOnlyExactRoleAndIsIdempotent()
    {
        await using var fixture = await AuthQualityPostgresFixture.CreateAsync();
        await using var scope = fixture.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        var config = Config(db.Database.GetConnectionString()!);
        using var output = new StringWriter();
        const string roleArgument = "--register-cloud-config-console-role-only";

        Assert.Equal(0, await CloudConfigRegistrationCommand.RunAsync([roleArgument], config, Environment(), output));
        Assert.Equal(0, await CloudConfigRegistrationCommand.RunAsync([roleArgument], config, Environment(), output));

        Assert.Equal("cloud-admin", (await db.Roles.AsNoTracking().SingleAsync()).Name);
        Assert.Empty(await db.Users.ToListAsync());
        Assert.Empty(await db.UserRoles.ToListAsync());
        Assert.Empty(await db.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync());
        Assert.Empty(await db.Set<OpenIddictEntityFrameworkCoreScope>().ToListAsync());
        Assert.Contains("cloud-config-console-role-only-v1", output.ToString());
    }

    [PostgresFact]
    public async Task RegistersOnlyExistingConsoleAndFiveScopesAndReentryPreservesStoredSecrets()
    {
        await using var fixture=await AuthQualityPostgresFixture.CreateAsync();await using var scope=fixture.Services.CreateAsyncScope();
        var db=scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();var apps=scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        foreach(var id in new[]{FirstPartyClients.CloudConsoleWeb,FirstPartyClients.MeWeb})
            await apps.CreateAsync(new OpenIddictApplicationDescriptor {ClientId=id,ClientType=ClientTypes.Confidential,ClientSecret="existing-fixture-secret",Permissions={Permissions.GrantTypes.AuthorizationCode,Permissions.GrantTypes.RefreshToken,Permissions.Endpoints.EndSession}});
        var rows=await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().ToListAsync();
        var consoleBefore=rows.Single(a=>a.ClientId==FirstPartyClients.CloudConsoleWeb);var otherBefore=rows.Single(a=>a.ClientId==FirstPartyClients.MeWeb);
        using var output=new StringWriter();var connection=db.Database.GetConnectionString()!;
        for(var i=0;i<2;i++)Assert.Equal(0,await CloudConfigRegistrationCommand.RunAsync([CloudConfigRegistrationCommand.Argument],Config(connection),Environment(),output));
        db.ChangeTracker.Clear();var after=await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().ToListAsync();
        var console=after.Single(a=>a.ClientId==FirstPartyClients.CloudConsoleWeb);var other=after.Single(a=>a.ClientId==FirstPartyClients.MeWeb);
        Assert.Equal(consoleBefore.ClientSecret,console.ClientSecret);Assert.Equal(consoleBefore.RedirectUris,console.RedirectUris);
        Assert.Equal(otherBefore.Permissions,other.Permissions);Assert.Equal(otherBefore.ClientSecret,other.ClientSecret);Assert.Equal(otherBefore.ConcurrencyToken,other.ConcurrencyToken);
        foreach(var name in CloudConfigScopes.All)Assert.Contains(Permissions.Prefixes.Scope+name,console.Permissions!);
        var client=await apps.FindByClientIdAsync(CloudConfigScopes.IntrospectionClient);Assert.NotNull(client);
        Assert.Equal(Permissions.Endpoints.Introspection,Assert.Single(await apps.GetPermissionsAsync(client)));
        Assert.True(await apps.ValidateClientSecretAsync(client,"cloud-config-command-fixture"));
        Assert.Equal(5,await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());
        Assert.Empty(await db.Roles.ToListAsync());Assert.DoesNotContain(connection,output.ToString());Assert.DoesNotContain("cloud-config-command-fixture",output.ToString());
    }
    [PostgresFact]
    public async Task ScopeDriftRollsBackNewScopesAndClientAndLeavesConsoleUnchanged()
    {
        await using var fixture=await AuthQualityPostgresFixture.CreateAsync();await using var scope=fixture.Services.CreateAsyncScope();
        var db=scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();var apps=scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();var scopes=scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        await apps.CreateAsync(new OpenIddictApplicationDescriptor {ClientId=FirstPartyClients.CloudConsoleWeb,ClientType=ClientTypes.Confidential,ClientSecret="existing-fixture-secret",Permissions={Permissions.GrantTypes.AuthorizationCode,Permissions.GrantTypes.RefreshToken}});
        await scopes.CreateAsync(new OpenIddictScopeDescriptor {Name=CloudConfigScopes.Execute,Resources={"wrong-resource"}});
        var before=await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync();
        using var output=new StringWriter();Assert.Equal(2,await CloudConfigRegistrationCommand.RunAsync([CloudConfigRegistrationCommand.Argument],Config(db.Database.GetConnectionString()!),Environment(),output));
        db.ChangeTracker.Clear();Assert.Equal(1,await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());Assert.Equal(1,await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
        var after=await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().SingleAsync();Assert.Equal(before.Permissions,after.Permissions);Assert.Equal(before.ConcurrencyToken,after.ConcurrencyToken);
        Assert.DoesNotContain("wrong-resource",output.ToString());
    }
}
