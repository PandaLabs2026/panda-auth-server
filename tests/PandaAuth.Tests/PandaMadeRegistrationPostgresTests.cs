using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Features.PortalClients;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PandaMadePostgresFactAttribute : FactAttribute
{
    public PandaMadePostgresFactAttribute()
    { if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PANDAMADE_TEST_POSTGRES"))) Skip = "Requires independent PandaMade test PostgreSQL"; }
}

public class PandaMadeRegistrationPostgresTests
{
    [PandaMadePostgresFact]
    public async Task RealDatabaseRegistrationIsMinimalAndIdempotent()
    {
        await using var fixture = await PandaMadeRegistrationDatabase.CreateAsync();
        await Register(fixture.Provider);
        await Register(fixture.Provider);
        await using var scope = fixture.Provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(2, await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var api = await manager.FindByClientIdAsync("pandamade-api");
        Assert.NotNull(api);
        Assert.Equal(new[] { OpenIddictConstants.Permissions.Endpoints.Introspection }, await manager.GetPermissionsAsync(api));
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        Assert.Equal(new[] { "pandamade-api" }, await scopes.GetResourcesAsync((await scopes.FindByNameAsync("pandamade.manage"))!));
    }

    [PandaMadePostgresFact]
    public async Task ConflictingExistingApiRollsBackScopeAndAdminWithoutOverwrite()
    {
        await using var fixture = await PandaMadeRegistrationDatabase.CreateAsync();
        await using (var scope = fixture.Provider.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(new OpenIddictApplicationDescriptor {
                ClientId = "pandamade-api", ClientType = OpenIddictConstants.ClientTypes.Confidential, ClientSecret = new string('c', 40),
                Permissions = { OpenIddictConstants.Permissions.GrantTypes.ClientCredentials, OpenIddictConstants.Permissions.Endpoints.Token } });
        await Assert.ThrowsAsync<InvalidOperationException>(() => Register(fixture.Provider));
        await using var verify = fixture.Provider.CreateAsyncScope();
        var db = verify.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
        Assert.Equal(0, await db.Set<OpenIddictEntityFrameworkCoreScope>().CountAsync());
        var manager = verify.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.True(await manager.ValidateClientSecretAsync((await manager.FindByClientIdAsync("pandamade-api"))!, new string('c',40)));
    }

    private static async Task Register(ServiceProvider provider)
    {
        var type = typeof(PandaAuthDbContext).Assembly.GetType("PandaAuth.Server.Features.PandaMade.PandaMadeRegistration");
        Assert.NotNull(type);
        var method = type.GetMethod("RegisterAsync"); Assert.NotNull(method);
        await using var scope = provider.CreateAsyncScope();
        await (Task)method.Invoke(null, [scope.ServiceProvider, new Uri("https://localhost:6501/"), new string('a',40), new string('b',40)])!;
    }
}

internal sealed class PandaMadeRegistrationDatabase : IAsyncDisposable
{
    private readonly string connection;
    public ServiceProvider Provider { get; }
    private PandaMadeRegistrationDatabase(string value) { connection = value; Provider = PortalClientCommand.Services(value); }
    public static async Task<PandaMadeRegistrationDatabase> CreateAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDAMADE_TEST_POSTGRES"));
        if (builder.Host != "127.0.0.1" || builder.Port != 43853 || builder.Username != "pandamade_fixture" || builder.Database != "postgres")
            throw new InvalidOperationException("Wrong PandaMade fixture boundary");
        var name = "panda_auth_pandamade_test_" + Guid.NewGuid().ToString("N");
        await using (var admin = new NpgsqlConnection(builder.ConnectionString))
        { await admin.OpenAsync(); await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", admin); await cmd.ExecuteNonQueryAsync(); }
        builder.Database = name;
        var fixture = new PandaMadeRegistrationDatabase(builder.ConnectionString);
        try { await using var scope = fixture.Provider.CreateAsyncScope(); await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.MigrateAsync(); return fixture; }
        catch { await fixture.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder(connection);
        if (builder.Host != "127.0.0.1" || builder.Port != 43853 || builder.Username != "pandamade_fixture" || !Regex.IsMatch(builder.Database!, "^panda_auth_pandamade_test_[a-f0-9]{32}$")) throw new InvalidOperationException("Wrong cleanup boundary");
        await using (var scope = Provider.CreateAsyncScope()) await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.EnsureDeletedAsync();
        await Provider.DisposeAsync();
    }
}
