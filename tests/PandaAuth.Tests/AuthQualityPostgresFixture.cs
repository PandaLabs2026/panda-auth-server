using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Tests;

internal sealed class AuthQualityPostgresFixture : IAsyncDisposable
{
    private readonly string connection;
    internal ServiceProvider Services { get; }

    private AuthQualityPostgresFixture(string connection, IInterceptor? interceptor)
    {
        this.connection = connection;
        var services = new ServiceCollection().AddLogging();
        services.AddDbContext<PandaAuthDbContext>(options =>
        {
            options.UseNpgsql(connection).UseOpenIddict();
            if (interceptor is not null) options.AddInterceptors(interceptor);
        });
        services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        Services = services.BuildServiceProvider();
    }

    internal static async Task<AuthQualityPostgresFixture> CreateAsync(IInterceptor? interceptor = null)
    {
        var builder = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
        PostgresTestBoundary.ValidateEndpoint(builder, PostgresTestBoundary.SharedMode);
        if (builder.Database != "postgres")
            throw new InvalidOperationException("Quality tests require the approved disposable loopback PostgreSQL cluster.");
        var name = "panda_auth_quality_" + Guid.NewGuid().ToString("N");
        await using (var admin = new NpgsqlConnection(builder.ConnectionString))
        {
            await admin.OpenAsync();
            await using var create = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", admin);
            await create.ExecuteNonQueryAsync();
        }
        builder.Database = name;
        var fixture = new AuthQualityPostgresFixture(builder.ConnectionString, interceptor);
        try
        {
            await using var scope = fixture.Services.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.MigrateAsync();
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }

    public async ValueTask DisposeAsync()
    {
        await Services.DisposeAsync();
        var builder = new NpgsqlConnectionStringBuilder(connection);
        PostgresTestBoundary.ValidateEndpoint(builder, PostgresTestBoundary.SharedMode);
        if (builder.Database is null || !Regex.IsMatch(builder.Database, "^panda_auth_quality_[0-9a-f]{32}$"))
            throw new InvalidOperationException("Refusing cleanup outside the task-owned quality database.");
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(connection).UseOpenIddict().Options);
        await db.Database.EnsureDeletedAsync();
    }
}
