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

public sealed class CloudControlRegistrationTests
{
    private static IHostEnvironment Environment() => new HostApplicationBuilder(new HostApplicationBuilderSettings
        { EnvironmentName=Environments.Development, DisableDefaults=true }).Environment;
    private static IConfiguration Config(string connection, bool? enabled=true, string issuer="https://auth.appliket.com/") =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>
        {
            ["ConnectionStrings:Migration"]=connection, ["Auth:Issuer"]=issuer,
            ["Auth:CloudControl:Enabled"]=enabled?.ToString(), ["Auth:Seed:Enabled"]="false"
        }).Build();

    [Theory]
    [InlineData("--register-cloud-control-only", "--migrate")]
    [InlineData("--register-cloud-control-unknown")]
    public async Task Malformed_command_refuses_before_starting_or_connecting(params string[] args)
    {
        using var output=new StringWriter();
        Assert.True(CloudControlRegistrationCommand.IsRequested(args));
        Assert.Equal(2,await CloudControlRegistrationCommand.RunAsync(args,new ConfigurationBuilder().Build(),Environment(),output));
        Assert.Contains("command_invalid",output.ToString());
    }

    [Theory]
    [InlineData(null,"https://auth.appliket.com/")]
    [InlineData(false,"https://auth.appliket.com/")]
    [InlineData(true,"https://wrong.invalid/")]
    public async Task Closed_or_wrong_issuer_refuses_without_connection_details(bool? enabled,string issuer)
    {
        using var output=new StringWriter();const string sensitive="Host=not-a-database;Password=must-not-appear";
        Assert.Equal(2,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(sensitive,enabled,issuer),Environment(),output));
        Assert.Contains("cloud_control_registration_closed",output.ToString());
        Assert.DoesNotContain(sensitive,output.ToString());Assert.DoesNotContain("must-not-appear",output.ToString());
    }

    [PostgresFact]
    public async Task Exact_existing_clients_gain_only_their_scopes_and_reentry_preserves_credentials_and_rows()
    {
        await using var fixture=await AuthQualityPostgresFixture.CreateAsync();
        await using var scope=fixture.Services.CreateAsyncScope();var services=scope.ServiceProvider;
        await PrepareAsync(services);
        var db=services.GetRequiredService<PandaAuthDbContext>();
        var before=await SnapshotAsync(db);using var output=new StringWriter();
        for(var i=0;i<2;i++)Assert.Equal(0,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(db.Database.GetConnectionString()!),Environment(),output));
        db.ChangeTracker.Clear();var after=await SnapshotAsync(db);
        Assert.Equal(before.Count,after.Count);
        foreach(var client in before.Keys)
        {
            Assert.True(before[client].ClientSecret==after[client].ClientSecret,"stored credential changed");
            Assert.Equal(before[client].RedirectUris,after[client].RedirectUris);
            Assert.Equal(before[client].PostLogoutRedirectUris,after[client].PostLogoutRedirectUris);
            Assert.Equal(before[client].Requirements,after[client].Requirements);
            Assert.Equal(before[client].Properties,after[client].Properties);
        }
        Assert.Equal(before[FirstPartyClients.MeWeb].ConcurrencyToken,after[FirstPartyClients.MeWeb].ConcurrencyToken);
        // Registration is a separate process. A reader created before it can retain
        // cached descriptors; this fresh owning reader verifies the committed state.
        var readers=new ServiceCollection().AddLogging();
        readers.AddDbContext<PandaAuthDbContext>(options=>options.UseNpgsql(db.Database.GetConnectionString()).UseOpenIddict());
        readers.AddOpenIddict().AddCore(options=>{options.DisableEntityCaching();options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>();});
        await using var readerProvider=readers.BuildServiceProvider();await using var readerScope=readerProvider.CreateAsyncScope();
        var apps=readerScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        foreach(var (client,expected) in new Dictionary<string,string[]>
        {
            [FirstPartyClients.CloudConsoleWeb]=["cloud.resources.read","cloud.resources.manage","cloud.health.check"],
            [FirstPartyClients.FleetAdminWeb]=["cloud.health.check"],
            [FirstPartyClients.CloudOperationWeb]=["cloud.resources.summary.read"],
            [FirstPartyClients.MeWeb]=[]
        })
        {
            var application=await apps.FindByClientIdAsync(client);Assert.NotNull(application);
            foreach(var name in new[]{"cloud.resources.read","cloud.resources.manage","cloud.resources.summary.read","cloud.health.check"})
                Assert.True(expected.Contains(name)==await apps.HasPermissionAsync(application,Permissions.Prefixes.Scope+name),
                    client+" "+name+" persisted="+after[client].Permissions!.Contains(Permissions.Prefixes.Scope+name,StringComparison.Ordinal));
            Assert.False(await apps.HasPermissionAsync(application,Permissions.GrantTypes.ClientCredentials));
            Assert.False(await apps.HasPermissionAsync(application,Permissions.Endpoints.Introspection));
        }
        var console=await apps.FindByClientIdAsync(FirstPartyClients.CloudConsoleWeb);Assert.NotNull(console);
        foreach(var name in new[]{"fleet.server.manage","fleet.platform.operate","fleet.approve"})
            Assert.True(await apps.HasPermissionAsync(console,Permissions.Prefixes.Scope+name));
        foreach(var name in new[]{"fleet.allocate","fleet.apply","fleet.retire","fleet.purge"})
            Assert.False(await apps.HasPermissionAsync(console,Permissions.Prefixes.Scope+name));
        var scopes=readerScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        foreach(var name in new[]{"cloud.resources.read","cloud.resources.manage","cloud.resources.summary.read","cloud.health.check"})
        {
            var resource=await scopes.FindByNameAsync(name);Assert.NotNull(resource);
            Assert.Equal("fleet-api",Assert.Single(await scopes.GetResourcesAsync(resource)));
        }
        Assert.Empty(await db.Users.ToListAsync());Assert.Empty(await db.Roles.ToListAsync());
        var first=after.ToDictionary(x=>x.Key,x=>x.Value.ConcurrencyToken);
        Assert.Equal(0,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(db.Database.GetConnectionString()!),Environment(),output));
        db.ChangeTracker.Clear();foreach(var row in await SnapshotAsync(db))Assert.Equal(first[row.Key],row.Value.ConcurrencyToken);
        Assert.DoesNotContain(db.Database.GetConnectionString()!,output.ToString());
        Assert.DoesNotContain("existing-fixture-secret",output.ToString());
    }

    [PostgresFact]
    public async Task Wrong_scope_resource_rolls_back_the_whole_group_without_rewriting_clients()
    {
        await using var fixture=await AuthQualityPostgresFixture.CreateAsync();await using var scope=fixture.Services.CreateAsyncScope();
        var services=scope.ServiceProvider;await PrepareAsync(services);
        var db=services.GetRequiredService<PandaAuthDbContext>();var before=await SnapshotAsync(db);
        await services.GetRequiredService<IOpenIddictScopeManager>().CreateAsync(new OpenIddictScopeDescriptor
            {Name="cloud.health.check",Resources={"wrong-resource"}});
        var count=await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync();using var output=new StringWriter();
        Assert.Equal(2,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(db.Database.GetConnectionString()!),Environment(),output));
        db.ChangeTracker.Clear();Assert.Equal(count,await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());
        foreach(var row in await SnapshotAsync(db))
        {
            Assert.Equal(before[row.Key].Permissions,row.Value.Permissions);
            Assert.Equal(before[row.Key].ConcurrencyToken,row.Value.ConcurrencyToken);
        }
        Assert.DoesNotContain("wrong-resource",output.ToString());
    }

    [PostgresFact]
    public async Task Existing_Operation_global_read_drift_is_not_silently_removed_or_accepted()
    {
        await using var fixture=await AuthQualityPostgresFixture.CreateAsync();await using var scope=fixture.Services.CreateAsyncScope();
        var services=scope.ServiceProvider;await PrepareAsync(services);var apps=services.GetRequiredService<IOpenIddictApplicationManager>();
        var application=(await apps.FindByClientIdAsync(FirstPartyClients.CloudOperationWeb))!;
        var descriptor=new OpenIddictApplicationDescriptor();await apps.PopulateAsync(descriptor,application);
        descriptor.Permissions.Add(Permissions.Prefixes.Scope+"cloud.resources.read");await apps.PopulateAsync(application,descriptor);await apps.UpdateAsync(application);
        var db=services.GetRequiredService<PandaAuthDbContext>();var before=await SnapshotAsync(db);using var output=new StringWriter();
        Assert.Equal(2,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(db.Database.GetConnectionString()!),Environment(),output));
        db.ChangeTracker.Clear();Assert.Equal(8,await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());
        foreach(var row in await SnapshotAsync(db))Assert.Equal(before[row.Key].ConcurrencyToken,row.Value.ConcurrencyToken);
    }

    [PostgresFact]
    public async Task A_late_client_write_failure_rolls_back_new_scopes_and_earlier_client_updates()
    {
        await using var fixture=await AuthQualityPostgresFixture.CreateAsync();await using var scope=fixture.Services.CreateAsyncScope();
        var services=scope.ServiceProvider;await PrepareAsync(services);var db=services.GetRequiredService<PandaAuthDbContext>();
        var before=await SnapshotAsync(db);
        var entity=db.Model.FindEntityType(typeof(OpenIddictEntityFrameworkCoreApplication))!;
        var table=entity.GetTableName()!;var column=entity.FindProperty(nameof(OpenIddictEntityFrameworkCoreApplication.ClientId))!.GetColumnName();
        using var quotes=new Npgsql.NpgsqlCommandBuilder();
        var sql=$"""
            create function cloud_control_test_reject() returns trigger language plpgsql as $body$
            begin
              if NEW.{quotes.QuoteIdentifier(column)}='cloud-operation-web' then raise exception 'fixture-write-refused'; end if;
              return NEW;
            end; $body$;
            create trigger cloud_control_test_reject before update on {quotes.QuoteIdentifier(table)}
            for each row execute function cloud_control_test_reject();
            """;
        await db.Database.ExecuteSqlRawAsync(sql);using var output=new StringWriter();
        Assert.Equal(2,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(db.Database.GetConnectionString()!),Environment(),output));
        db.ChangeTracker.Clear();Assert.Equal(8,await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());
        foreach(var row in await SnapshotAsync(db))
        {
            Assert.Equal(before[row.Key].Permissions,row.Value.Permissions);
            Assert.Equal(before[row.Key].ConcurrencyToken,row.Value.ConcurrencyToken);
        }
        Assert.DoesNotContain("fixture-write-refused",output.ToString());
    }

    [PostgresFact]
    public async Task Missing_existing_clients_and_machine_Web_grants_refuse_without_creating_replacements()
    {
        foreach(var mode in new[]{"missing-operation","missing-api","machine-grant","introspection"})
        {
            await using var fixture=await AuthQualityPostgresFixture.CreateAsync();await using var scope=fixture.Services.CreateAsyncScope();
            var services=scope.ServiceProvider;await PrepareAsync(services);var db=services.GetRequiredService<PandaAuthDbContext>();
            var apps=services.GetRequiredService<IOpenIddictApplicationManager>();
            var id=mode=="missing-api"?FirstPartyClients.FleetApi:FirstPartyClients.CloudOperationWeb;
            var app=(await apps.FindByClientIdAsync(id))!;
            if(mode.StartsWith("missing",StringComparison.Ordinal))await apps.DeleteAsync(app);
            else
            {
                var descriptor=new OpenIddictApplicationDescriptor();await apps.PopulateAsync(descriptor,app);
                descriptor.Permissions.Add(mode=="machine-grant"?Permissions.GrantTypes.ClientCredentials:Permissions.Endpoints.Introspection);
                await apps.PopulateAsync(app,descriptor);await apps.UpdateAsync(app);
            }
            var before=await SnapshotAsync(db);using var output=new StringWriter();
            Assert.Equal(2,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(db.Database.GetConnectionString()!),Environment(),output));
            db.ChangeTracker.Clear();var after=await SnapshotAsync(db);Assert.Equal(before.Count,after.Count);
            Assert.Equal(8,await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());
            foreach(var row in after)Assert.Equal(before[row.Key].ConcurrencyToken,row.Value.ConcurrencyToken);
        }
    }

    [PostgresFact]
    public async Task Pending_schema_refuses_without_migrating_or_creating_registration_rows()
    {
        await using var fixture=await AuthQualityPostgresFixture.CreateAsync(migrate:false);
        await using var scope=fixture.Services.CreateAsyncScope();var db=scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        using var output=new StringWriter();
        Assert.Equal(2,await CloudControlRegistrationCommand.RunAsync(["--register-cloud-control-only"],Config(db.Database.GetConnectionString()!),Environment(),output));
        await using var connection=new Npgsql.NpgsqlConnection(db.Database.GetConnectionString());await connection.OpenAsync();
        await using var query=new Npgsql.NpgsqlCommand("select count(*) from pg_tables where schemaname='public'",connection);
        Assert.Equal(0L,(long)(await query.ExecuteScalarAsync())!);
        Assert.DoesNotContain(db.Database.GetConnectionString()!,output.ToString());
    }

    private static async Task<Dictionary<string,OpenIddictEntityFrameworkCoreApplication>> SnapshotAsync(PandaAuthDbContext db) =>
        (await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().ToListAsync()).ToDictionary(row=>row.ClientId!);

    internal static async Task PrepareAsync(IServiceProvider services)
    {
        var apps=services.GetRequiredService<IOpenIddictApplicationManager>();var scopes=services.GetRequiredService<IOpenIddictScopeManager>();
        foreach(var name in PandaAuthScopes.FleetAll)
            await scopes.CreateAsync(new OpenIddictScopeDescriptor {Name=name,Resources={PandaAuthScopes.FleetApi}});
        await apps.CreateAsync(new OpenIddictApplicationDescriptor {ClientId=FirstPartyClients.FleetApi,ClientType=ClientTypes.Confidential,
            ClientSecret="api-fixture-secret",Permissions={Permissions.Endpoints.Introspection}});
        foreach(var client in new[]{FirstPartyClients.CloudConsoleWeb,FirstPartyClients.FleetAdminWeb,FirstPartyClients.CloudOperationWeb,FirstPartyClients.MeWeb})
        {
            var descriptor=new OpenIddictApplicationDescriptor {ClientId=client,ClientType=ClientTypes.Confidential,
                ClientSecret="existing-fixture-secret",ConsentType=ConsentTypes.Implicit,
                RedirectUris={new Uri("https://fixture.invalid/"+client+"/callback")},
                PostLogoutRedirectUris={new Uri("https://fixture.invalid/"+client+"/logout")},
                Permissions={Permissions.Endpoints.Authorization,Permissions.Endpoints.Token,Permissions.Endpoints.EndSession,Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode,Permissions.GrantTypes.RefreshToken,Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Profile,Permissions.Prefixes.Scope+Scopes.OfflineAccess},
                Requirements={Requirements.Features.ProofKeyForCodeExchange}};
            if(client==FirstPartyClients.FleetAdminWeb)
                foreach(var name in PandaAuthScopes.FleetAll)descriptor.Permissions.Add(Permissions.Prefixes.Scope+name);
            await apps.CreateAsync(descriptor);
        }
    }
}
