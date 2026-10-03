using System.Security.Cryptography;
using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Features.PortalClients;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public class PortalClientRegistrationPostgresTests
{
    [PostgresFact]
    public async Task Register_ActuallyCreatesPublicClientAndDurableOperation()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var raw = Request();
        var receipt = await fixture.Service.ExecuteAsync(raw);
        await using var scope = fixture.Provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
        Assert.Equal(1, await db.AdminAuditLogs.CountAsync());
        Assert.EndsWith("\n", receipt);
    }

    [PostgresFact]
    public async Task DuplicateRequestKeys_AreRejectedBeforeAnyWrite()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var raw = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Request()).Replace("{", "{\"schemaVersion\":1,", StringComparison.Ordinal));
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.Service.ExecuteAsync(raw));
    }

    [PostgresFact]
    public async Task LostReceipt_FreshScopeRecoversExactOriginalBytesAndClassification()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var raw = Request();
        var now = DateTimeOffset.UtcNow;
        var original = await new PortalClientRegistrationService(fixture.Provider.GetRequiredService<IServiceScopeFactory>(), new FixedRegistrationClock(now.AddMinutes(-1))).ExecuteAsync(raw);
        Assert.Equal(original, await new PortalClientRegistrationService(fixture.Provider.GetRequiredService<IServiceScopeFactory>(), new FixedRegistrationClock(now.AddMinutes(1))).ExecuteAsync(raw));
        using var receipt = JsonDocument.Parse(original);
        Assert.Equal("created", receipt.RootElement.GetProperty("result").GetString());
        Assert.Equal(PortalClientRequest.Hash(raw), receipt.RootElement.GetProperty("requestDigest").GetString());
        Assert.Equal((1, 1), await fixture.CountsAsync());
        var changed = Encoding.UTF8.GetBytes(" " + Encoding.UTF8.GetString(raw));
        await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(changed));
        Assert.Equal((1, 1), await fixture.CountsAsync());
    }

    [PostgresFact]
    public async Task MissingOriginalAudit_WithPersistentCreationMarkerCannotGenerateAnotherClient()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var raw = Request();
        await fixture.Service.ExecuteAsync(raw);
        await using (var scope = fixture.Provider.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.ExecuteDeleteAsync();
        await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(raw));
        Assert.Equal((1, 0), await fixture.CountsAsync());
    }

    [PostgresFact]
    public async Task CommitAcknowledgementUnknown_BeforeAndAfterActualCommitUsesFreshLookup()
    {
        foreach (var afterCommit in new[] { false, true })
        {
            await using var fixture = await RegistrationDatabase.CreateAsync();
            var boundary = new UnknownCommitBoundary(afterCommit);
            var receipt = await fixture.WithBoundary(boundary).ExecuteAsync(Request());
            Assert.Equal(1, boundary.Retries);
            Assert.True(boundary.Contexts.Distinct().Count() >= 2);
            Assert.Equal((1, 1), await fixture.CountsAsync());
            Assert.Contains("\"result\":\"created\"", receipt, StringComparison.Ordinal);
        }
    }

    [PostgresFact]
    public async Task SameOperationConcurrentIndependentConnections_OnlyOneOriginalClientAndResult()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var boundary = new ConcurrentLookupBoundary();
        var raw = Request();
        var results = await Task.WhenAll(fixture.WithBoundary(boundary).ExecuteAsync(raw), fixture.WithBoundary(boundary).ExecuteAsync(raw));
        Assert.Equal(results[0], results[1]);
        Assert.Equal((1, 1), await fixture.CountsAsync());
        Assert.True(boundary.Retries >= 1);
        Assert.True(boundary.Contexts.Distinct().Count() >= 3);
        Assert.Equal(2, boundary.FirstConnections.Distinct().Count());
    }

    [PostgresFact]
    public async Task ExistingExactClient_RecoversExistingAndCannotBeUnregistered()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        await using (var scope = fixture.Provider.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(PortalClientRequest.Descriptor("owned-existing"));
        var raw = Request("owned-existing");
        var receipt = await fixture.Service.ExecuteAsync(raw);
        Assert.Equal(receipt, await fixture.Service.ExecuteAsync(raw));
        using var json = JsonDocument.Parse(receipt);
        Assert.Equal("existing", json.RootElement.GetProperty("result").GetString());
        await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(Rollback(receipt), true));
        Assert.Equal((1, 1), await fixture.CountsAsync());
    }

    [PostgresFact]
    public async Task ExistingMismatchedRegistration_IsNeverOverwrittenOrRecordedAsSuccess()
    {
        foreach (var field in new[] { "secret", "type", "consent", "grant", "redirect", "pkce" })
        {
            await using var fixture = await RegistrationDatabase.CreateAsync();
            await using (var scope = fixture.Provider.CreateAsyncScope())
            {
                var descriptor = PortalClientRequest.Descriptor("mismatched-existing");
                if (field == "secret") { descriptor.ClientType = "confidential"; descriptor.ClientSecret = "synthetic-secret"; }
                if (field == "type") { descriptor.ClientType = "confidential"; descriptor.ClientSecret = "synthetic-type-secret"; }
                if (field == "consent") descriptor.ConsentType = "explicit";
                if (field == "grant") descriptor.Permissions.Add("gt:refresh_token");
                if (field == "redirect") descriptor.RedirectUris.Add(new Uri("https://foreign.invalid/callback"));
                if (field == "pkce") descriptor.Requirements.Clear();
                await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(descriptor);
            }
            await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(Request("mismatched-existing")));
            Assert.Equal((1, 0), await fixture.CountsAsync());
        }
    }

    [PostgresFact]
    public async Task CreatedOnlyRollback_IsAtomicStableTerminalAndCannotRecreate()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var raw = Request();
        var receipt = await fixture.Service.ExecuteAsync(raw);
        var rollback = Rollback(receipt);
        var terminal = await fixture.Service.ExecuteAsync(rollback, true);
        Assert.Equal(terminal, await fixture.Service.ExecuteAsync(rollback, true));
        await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(raw));
        Assert.Equal((0, 2), await fixture.CountsAsync());
        await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(Encoding.UTF8.GetBytes(" " + Encoding.UTF8.GetString(rollback)), true));
    }

    [PostgresFact]
    public async Task AuditInsertFailure_RollsBackCreateAndDeleteWithoutSuccessReceipt()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var raw = Request();
        await using (var provider = fixture.NewProvider(new AuditInsertFault(PortalClientRegistrationService.RegisterAction)))
        {
            var service = new PortalClientRegistrationService(provider.GetRequiredService<IServiceScopeFactory>(), TimeProvider.System);
            await Assert.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(raw));
        }
        Assert.Equal((0, 0), await fixture.CountsAsync());
        var receipt = await fixture.Service.ExecuteAsync(raw);
        await using (var provider = fixture.NewProvider(new AuditInsertFault(PortalClientRegistrationService.UnregisterAction)))
        {
            var service = new PortalClientRegistrationService(provider.GetRequiredService<IServiceScopeFactory>(), TimeProvider.System);
            await Assert.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(Rollback(receipt), true));
        }
        Assert.Equal((1, 1), await fixture.CountsAsync());
    }

    [PostgresFact]
    public async Task AuthorizationOrTokenReference_PreventsCascadeAndLeavesCountsUnchanged()
    {
        foreach (var tokenReference in new[] { false, true })
        {
            await using var fixture = await RegistrationDatabase.CreateAsync();
            var receipt = await fixture.Service.ExecuteAsync(Request());
            await using (var scope = fixture.Provider.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                var app = await db.Set<OpenIddictEntityFrameworkCoreApplication>().SingleAsync();
                if (tokenReference) await scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>().CreateAsync(new OpenIddictTokenDescriptor
                    { ApplicationId = app.Id, Status = "valid", Type = "refresh_token", Subject = "synthetic-subject" });
                else await scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>().CreateAsync(new OpenIddictAuthorizationDescriptor
                    { ApplicationId = app.Id, Status = "valid", Type = "permanent", Subject = "synthetic-subject" });
            }
            await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(Rollback(receipt), true));
            Assert.Equal((1, 1), await fixture.CountsAsync());
            await using var check = fixture.Provider.CreateAsyncScope();
            var context = check.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            Assert.Equal(tokenReference ? 1 : 0, await context.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync());
            Assert.Equal(tokenReference ? 0 : 1, await context.Set<OpenIddictEntityFrameworkCoreAuthorization>().CountAsync());
        }
    }

    [PostgresFact]
    public async Task HistoricalRecoveryAudit_IsRetainedAndExpiredFirstRequestCannotWrite()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var raw = Request();
        var receipt = await fixture.Service.ExecuteAsync(raw);
        await using (var scope = fixture.Provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            (await db.AdminAuditLogs.SingleAsync()).CreatedAt = DateTimeOffset.UtcNow.AddDays(-100);
            db.AdminAuditLogs.Add(new AdminAuditLog { Action = "other.action", ActorUserId = "fixture", CreatedAt = DateTimeOffset.UtcNow.AddDays(-100) });
            await db.SaveChangesAsync();
            Assert.Equal(1, await LoginLogRetentionService.PurgeAdminAuditAsync(db, DateTimeOffset.UtcNow.AddDays(-90), 1, CancellationToken.None));
        }
        Assert.Equal(receipt, await fixture.Service.ExecuteAsync(raw));
        var expired = new FixedRegistrationClock(DateTimeOffset.UtcNow.AddDays(2));
        var request = Request();
        await Assert.ThrowsAsync<PortalClientClosedException>(() => new PortalClientRegistrationService(fixture.Provider.GetRequiredService<IServiceScopeFactory>(), expired).ExecuteAsync(request));
        Assert.Equal((1, 1), await fixture.CountsAsync());
    }

    [PostgresFact]
    public async Task AlteredCreationMarkerDescriptorMissingAuditOrRollbackBinding_NeverDeletes()
    {
        foreach (var fault in new[] { "marker", "descriptor", "audit", "operationId", "requestDigest", "registrationDigest", "clientId" })
        {
            await using var fixture = await RegistrationDatabase.CreateAsync();
            var receipt = await fixture.Service.ExecuteAsync(Request());
            var rollback = Rollback(receipt);
            await using (var scope = fixture.Provider.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                var app = await db.Set<OpenIddictEntityFrameworkCoreApplication>().SingleAsync();
                if (fault == "marker") { app.Properties = "{}"; await db.SaveChangesAsync(); }
                if (fault == "descriptor")
                {
                    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                    var descriptor = new OpenIddictApplicationDescriptor(); await manager.PopulateAsync(descriptor, app);
                    descriptor.RedirectUris.Add(new Uri("https://foreign.invalid/callback")); await manager.UpdateAsync(app, descriptor);
                }
                if (fault == "audit") { db.AdminAuditLogs.Remove(await db.AdminAuditLogs.SingleAsync()); await db.SaveChangesAsync(); }
            }
            if (fault is "operationId" or "requestDigest" or "registrationDigest" or "clientId")
            {
                var fields = JsonSerializer.Deserialize<Dictionary<string, object?>>(rollback)!;
                fields[fault] = fault == "operationId" ? Guid.NewGuid().ToString("D") : fault == "clientId" ? "unrelated-owned-client" : new string('c', 64);
                rollback = JsonSerializer.SerializeToUtf8Bytes(fields);
            }
            await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.Service.ExecuteAsync(rollback, true));
            Assert.Equal((1, fault == "audit" ? 0 : 1), await fixture.CountsAsync());
        }
    }

    [PostgresFact]
    public async Task WholeTransactionRetryExhaustion_LeavesNoClientAndReturnsFixedRetryableFailure()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var boundary = new ExhaustedCommitBoundary();
        var failure = await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.WithBoundary(boundary).ExecuteAsync(Request()));
        Assert.Equal("retryable-operation-uncertain", failure.Message);
        Assert.Equal(4, boundary.Retries);
        Assert.Equal((0, 0), await fixture.CountsAsync());
    }

    [PostgresFact]
    public async Task ConcurrentRegistrationMutation_IsDetectedBySerializableFreshReadAndNeverDeleted()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var receipt = await fixture.Service.ExecuteAsync(Request());
        var boundary = new MutationBoundary(fixture);
        await Assert.ThrowsAsync<PortalClientClosedException>(() => fixture.WithBoundary(boundary).ExecuteAsync(Rollback(receipt), true));
        Assert.True(boundary.Retries >= 1);
        Assert.Equal((1, 1), await fixture.CountsAsync());
    }

    [PostgresFact]
    public async Task ActualCommandCoreComposition_OnlyCreatesClientAuditAndNoKeysUsersOrHostedServices()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        await using var provider = PortalClientCommand.Services(fixture.Connection);
        Assert.Empty(provider.GetServices<Microsoft.Extensions.Hosting.IHostedService>());
        Assert.Null(provider.GetService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>());
        await new PortalClientRegistrationService(provider.GetRequiredService<IServiceScopeFactory>(), TimeProvider.System).ExecuteAsync(Request());
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        Assert.Equal(0, await db.SigningKeys.CountAsync()); Assert.Equal(0, await db.Users.CountAsync()); Assert.Equal(0, await db.Roles.CountAsync());
        Assert.Equal((1, 1), await fixture.CountsAsync());
    }

    internal static byte[] Rollback(string receipt)
    {
        using var json = JsonDocument.Parse(receipt);
        var root = json.RootElement;
        var now = DateTimeOffset.UtcNow;
        var fields = new Dictionary<string, object?>();
        foreach (var name in new[] { "schemaVersion", "deploymentKind", "tenantId", "zone", "machineId", "operationId", "requestDigest", "registrationDigest", "clientId", "authMetaSource", "authServerSource", "planReference", "executionReference", "executor" })
            fields[name] = root.GetProperty(name).Clone();
        fields["maintenanceStartUtc"] = PortalClientRequest.Timestamp(now.AddMinutes(-5));
        fields["maintenanceEndUtc"] = PortalClientRequest.Timestamp(now.AddMinutes(5));
        fields["validUntilUtc"] = PortalClientRequest.Timestamp(now.AddHours(1));
        return JsonSerializer.SerializeToUtf8Bytes(fields);
    }

    internal static byte[] Request(string? clientId = null, string? operation = null)
    {
        var now = DateTimeOffset.UtcNow;
        var fields = new Dictionary<string, object?>
        {
            ["schemaVersion"] = 1, ["deploymentKind"] = "legacy-t0000-portal", ["tenantId"] = "t0000",
            ["zone"] = "s001", ["machineId"] = "tcloud-sh-01", ["operationId"] = operation ?? Guid.NewGuid().ToString("D"),
            ["issuer"] = "https://t0000-auth.s001.pandalabs.cn/", ["redirectUri"] = "https://t0000.s001.pandalabs.cn/callback",
            ["postLogoutRedirectUri"] = "https://t0000.s001.pandalabs.cn/callback/logout",
            ["authMetaSource"] = new string('a', 40), ["authServerSource"] = new string('b', 40),
            ["planReference"] = "test-plan", ["executionReference"] = "test-execution", ["executor"] = "jiayuhu@tcloud-sh-01",
            ["maintenanceStartUtc"] = now.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["maintenanceEndUtc"] = now.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["validUntilUtc"] = now.AddDays(1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
        };
        if (clientId is not null) fields["clientId"] = clientId;
        return JsonSerializer.SerializeToUtf8Bytes(fields);
    }
}

internal sealed class RegistrationDatabase : IAsyncDisposable
{
    private readonly string _connection;
    internal string Connection => _connection;
    public ServiceProvider Provider { get; }
    public PortalClientRegistrationService Service => new(Provider.GetRequiredService<IServiceScopeFactory>(), TimeProvider.System);
    public PortalClientRegistrationService WithBoundary(PortalClientTransactionBoundary boundary) => new(Provider.GetRequiredService<IServiceScopeFactory>(), TimeProvider.System, boundary);
    public async Task<(int Clients, int Audits)> CountsAsync()
    {
        await using var scope = Provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        return (await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync(), await db.AdminAuditLogs.CountAsync());
    }
    public ServiceProvider NewProvider(IInterceptor? interceptor = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PandaAuthDbContext>(o => { o.UseNpgsql(_connection).UseOpenIddict(); if (interceptor is not null) o.AddInterceptors(interceptor); });
        services.AddOpenIddict().AddCore(o => { o.DisableEntityCaching(); o.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>(); });
        services.AddScoped<AdminAuditWriter>();
        return services.BuildServiceProvider();
    }
    private RegistrationDatabase(string connection)
    {
        _connection = connection;
        Provider = NewProvider();
    }
    public static async Task<RegistrationDatabase> CreateAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
        if (builder.Host != "127.0.0.1" || builder.Port != 43823 || builder.Database != "postgres") throw new InvalidOperationException("Wrong task PG boundary.");
        var name = "panda_auth_registration_test_" + Guid.NewGuid().ToString("N");
        await using (var connection = new NpgsqlConnection(builder.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
            await command.ExecuteNonQueryAsync();
        }
        builder.Database = name;
        var fixture = new RegistrationDatabase(builder.ConnectionString);
        try
        {
            await using var scope = fixture.Provider.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.MigrateAsync();
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder(_connection);
        if (builder.Host != "127.0.0.1" || builder.Port != 43823 || builder.Database is null || !Regex.IsMatch(builder.Database, "^panda_auth_registration_test_[0-9a-f]{32}$")) throw new InvalidOperationException("Wrong task PG cleanup boundary.");
        await using (var scope = Provider.CreateAsyncScope()) await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.EnsureDeletedAsync();
        await Provider.DisposeAsync();
    }
}

internal sealed class FixedRegistrationClock(DateTimeOffset now) : TimeProvider
{ public override DateTimeOffset GetUtcNow() => now; }
internal sealed class UnknownCommitBoundary(bool afterCommit) : PortalClientTransactionBoundary
{
    private int _commits;
    public int Retries;
    public List<Guid> Contexts { get; } = [];
    internal override Task AfterLookupAsync(int attempt, PandaAuthDbContext db) { Contexts.Add(db.ContextId.InstanceId); return Task.CompletedTask; }
    internal override async Task CommitAsync(IDbContextTransaction transaction)
    {
        if (Interlocked.Increment(ref _commits) == 1)
        { if (afterCommit) await transaction.CommitAsync(); throw new PortalClientCommitUncertainException(); }
        await transaction.CommitAsync();
    }
    internal override void Retrying() => Retries++;
}
internal sealed class ConcurrentLookupBoundary : PortalClientTransactionBoundary
{
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _arrivals;
    public int Retries;
    public List<Guid> Contexts { get; } = [];
    public List<int> FirstConnections { get; } = [];
    internal override async Task AfterLookupAsync(int attempt, PandaAuthDbContext db)
    {
        lock (Contexts) Contexts.Add(db.ContextId.InstanceId);
        if (attempt != 0) return;
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction!.GetDbTransaction(); command.CommandText = "select pg_backend_pid()";
        var pid = (int)(await command.ExecuteScalarAsync())!;
        lock (FirstConnections) FirstConnections.Add(pid);
        if (Interlocked.Increment(ref _arrivals) == 2) _ready.TrySetResult();
        await _ready.Task.WaitAsync(TimeSpan.FromSeconds(20));
    }
    internal override void Retrying() => Interlocked.Increment(ref Retries);
}
internal sealed class AuditInsertFault(string action) : SaveChangesInterceptor
{
    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        if (eventData.Context!.ChangeTracker.Entries<AdminAuditLog>().Any(e => e.State == EntityState.Added && e.Entity.Action == action))
            throw new InvalidOperationException("isolated-audit-insert-fault");
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }
}

internal sealed class ExhaustedCommitBoundary : PortalClientTransactionBoundary
{
    public int Retries;
    internal override Task CommitAsync(IDbContextTransaction transaction) => throw new PortalClientCommitUncertainException();
    internal override void Retrying() => Retries++;
}
internal sealed class MutationBoundary(RegistrationDatabase fixture) : PortalClientTransactionBoundary
{
    public int Retries;
    internal override async Task AfterLookupAsync(int attempt, PandaAuthDbContext db)
    {
        if (attempt != 0) return;
        await using var scope = fixture.Provider.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = await scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Set<OpenIddictEntityFrameworkCoreApplication>().SingleAsync();
        var descriptor = new OpenIddictApplicationDescriptor(); await manager.PopulateAsync(descriptor, application);
        descriptor.RedirectUris.Add(new Uri("https://foreign.invalid/callback")); await manager.UpdateAsync(application, descriptor);
    }
    internal override void Retrying() => Retries++;
}
