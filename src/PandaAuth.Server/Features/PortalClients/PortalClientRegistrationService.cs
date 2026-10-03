using System.Data;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using static PandaAuth.Server.Features.PortalClients.PortalClientRequest;

namespace PandaAuth.Server.Features.PortalClients;

// Narrow commit/lookup boundary used by isolated tests; production has no runtime fault switches.
internal class PortalClientTransactionBoundary
{
    internal virtual Task AfterLookupAsync(int attempt, PandaAuthDbContext db) => Task.CompletedTask;
    internal virtual Task CommitAsync(IDbContextTransaction transaction) => transaction.CommitAsync();
    internal virtual void Retrying() { }
}
internal sealed class PortalClientCommitUncertainException : Exception;
internal sealed record PortalOperationRecord(string RequestDigest, string ReceiptRaw, string ApplicationId, string ValidUntilUtc);

internal sealed class PortalClientRegistrationService(IServiceScopeFactory scopes, TimeProvider clock, PortalClientTransactionBoundary? boundary = null)
{
    internal const string RegisterAction = "portal.client.register";
    internal const string UnregisterAction = "portal.client.unregister";
    internal const string TargetType = "portal-client-operation";
    internal const string CreationProperty = "pandalabs.t0000-portal.creation";
    private readonly PortalClientTransactionBoundary _boundary = boundary ?? new();

    internal async Task<string> ExecuteAsync(byte[] raw, bool unregister = false)
    {
        var request = Parse(raw, unregister, clock.GetUtcNow());
        for (var attempt = 0; attempt < 4; attempt++)
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var audit = scope.ServiceProvider.GetRequiredService<AdminAuditWriter>();
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            try
            {
                var registration = await db.AdminAuditLogs.AsNoTracking().Where(log => log.Action == RegisterAction &&
                    log.TargetType == TargetType && log.TargetId == request.OperationId).SingleOrDefaultAsync();
                var terminal = await db.AdminAuditLogs.AsNoTracking().Where(log => log.Action == UnregisterAction &&
                    log.TargetType == TargetType && log.TargetId == request.OperationId).SingleOrDefaultAsync();
                await _boundary.AfterLookupAsync(attempt, db);
                string receipt;
                if (unregister) receipt = await UnregisterAsync(request, registration, terminal, db, manager, audit);
                else
                {
                    Require(terminal is null, "operation-revoked");
                    if (registration is not null) receipt = await RecoverAsync(request, registration, db, manager);
                    else
                    {
                        Require(request.InWindow(clock.GetUtcNow()), "outside-maintenance-window");
                        // An orphaned creation marker is evidence of an inconsistent committed operation,
                        // never authority to generate a second client after its recovery audit is lost.
                        var marked = await db.Set<OpenIddictEntityFrameworkCoreApplication>()
                            .FromSqlInterpolated($"SELECT * FROM \"OpenIddictApplications\" WHERE \"Properties\"::jsonb -> {CreationProperty} ->> 'operationId' = {request.OperationId}")
                            .AnyAsync();
                        Require(!marked, "missing-operation-audit");
                        var id = request.ClientId ?? "portal-" + Guid.NewGuid().ToString("N");
                        var application = await LockedApplicationAsync(db, id);
                        var result = application is null ? "created" : "existing";
                        var descriptor = Descriptor(id);
                        if (application is null)
                        {
                            descriptor.Properties[CreationProperty] = JsonSerializer.SerializeToElement(new
                            {
                                deploymentKind = Kind, operationId = request.OperationId, requestDigest = request.Digest,
                                registrationDigest = RegistrationDigest(descriptor),
                            });
                            application = (OpenIddictEntityFrameworkCoreApplication)await manager.CreateAsync(descriptor);
                        }
                        descriptor = await ReadMatchingAsync(manager, application);
                        receipt = Receipt(request, descriptor, result, clock.GetUtcNow());
                        var record = new PortalOperationRecord(request.Digest, receipt, application.Id!, request["validUntilUtc"]);
                        await audit.RecordAsync(Entry(RegisterAction, request, record));
                    }
                }
                await _boundary.CommitAsync(transaction);
                return receipt; // stdout is delivered only after confirmed commit; original bytes come from audit on retry.
            }
            catch (Exception error) when (Retryable(error))
            {
                // Dispose the entire failed/uncertain transaction and context before persistent lookup in a new scope.
                _boundary.Retrying();
                if (attempt == 3) throw new PortalClientClosedException("retryable-operation-uncertain");
            }
        }
        throw new PortalClientClosedException("retryable-operation-uncertain");
    }

    private static bool Retryable(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is PortalClientCommitUncertainException or DbUpdateConcurrencyException or TimeoutException) return true;
            if (current is PostgresException pg && pg.SqlState is "40001" or "40P01" or "23505") return true;
            if (current is NpgsqlException { IsTransient: true }) return true;
        }
        return false;
    }
    private static AdminAuditLog Entry(string action, PortalClientRequest request, PortalOperationRecord record)
        => new() { ActorUserId = Executor, ActorUserName = Executor, Action = action, TargetType = TargetType,
            TargetId = request.OperationId, Detail = JsonSerializer.Serialize(record) };
    private static PortalOperationRecord Record(AdminAuditLog log)
    {
        Require(log.ActorUserId == Executor && log.TargetType == TargetType && log.Detail is not null, "invalid-operation-audit");
        var record = JsonSerializer.Deserialize<PortalOperationRecord>(log.Detail!) ?? throw new PortalClientClosedException("invalid-operation-audit");
        Require(!string.IsNullOrEmpty(record.ApplicationId) && record.RequestDigest.Length == 64 && record.ReceiptRaw.EndsWith('\n'), "invalid-operation-audit");
        _ = Utc(record.ValidUntilUtc);
        return record;
    }
    private static async Task<OpenIddictEntityFrameworkCoreApplication?> LockedApplicationAsync(PandaAuthDbContext db, string clientId)
        => await db.Set<OpenIddictEntityFrameworkCoreApplication>()
            .FromSqlInterpolated($"SELECT * FROM \"OpenIddictApplications\" WHERE \"ClientId\" = {clientId} FOR UPDATE").SingleOrDefaultAsync();
    private static async Task<OpenIddictApplicationDescriptor> ReadMatchingAsync(IOpenIddictApplicationManager manager, OpenIddictEntityFrameworkCoreApplication application)
    {
        var descriptor = new OpenIddictApplicationDescriptor();
        await manager.PopulateAsync(descriptor, application);
        Require(application.ClientSecret is null && descriptor.ClientSecret is null && descriptor.ClientId is not null &&
            RegistrationDigest(descriptor) == RegistrationDigest(Descriptor(descriptor.ClientId)), "registration-mismatch");
        return descriptor;
    }
    private static JsonElement ReceiptJson(PortalOperationRecord record) => ClosedJson(Encoding.UTF8.GetBytes(record.ReceiptRaw));
    private static void BindOriginal(PortalClientRequest request, PortalOperationRecord original, JsonElement receipt)
    {
        Require(receipt.GetProperty("operationId").GetString() == request.OperationId &&
            receipt.GetProperty("deploymentKind").GetString() == Kind && receipt.GetProperty("tenantId").GetString() == "t0000" &&
            receipt.GetProperty("zone").GetString() == "s001" && receipt.GetProperty("machineId").GetString() == "tcloud-sh-01" &&
            receipt.GetProperty("executor").GetString() == Executor && receipt.GetProperty("requestDigest").GetString() == original.RequestDigest &&
            receipt.GetProperty("authMetaSource").GetString() == request["authMetaSource"] &&
            receipt.GetProperty("authServerSource").GetString() == request["authServerSource"], "operation-binding-mismatch");
    }
    private async Task<string> RecoverAsync(PortalClientRequest request, AdminAuditLog registration, PandaAuthDbContext db, IOpenIddictApplicationManager manager)
    {
        var original = Record(registration); var receipt = ReceiptJson(original);
        BindOriginal(request, original, receipt);
        Require(original.RequestDigest == request.Digest && clock.GetUtcNow() <= Utc(original.ValidUntilUtc), "operation-binding-mismatch");
        Require(receipt.GetProperty("planReference").GetString() == request["planReference"] &&
            receipt.GetProperty("executionReference").GetString() == request["executionReference"], "operation-binding-mismatch");
        var id = receipt.GetProperty("clientId").GetString()!;
        var application = await LockedApplicationAsync(db, id);
        Require(application is not null && application.Id == original.ApplicationId, "registered-client-missing");
        var descriptor = await ReadMatchingAsync(manager, application!);
        Require(RegistrationDigest(descriptor) == receipt.GetProperty("registrationDigest").GetString(), "registration-mismatch");
        if (receipt.GetProperty("result").GetString() == "created") ValidateCreation(application!, request.OperationId, request.Digest, RegistrationDigest(descriptor));
        else Require(receipt.GetProperty("result").GetString() == "existing", "invalid-original-result");
        return original.ReceiptRaw;
    }
    private static void ValidateCreation(OpenIddictEntityFrameworkCoreApplication application, string operation, string requestDigest, string registrationDigest)
    {
        Require(application.Properties is not null, "missing-creation-marker");
        var properties = ClosedJson(Encoding.UTF8.GetBytes(application.Properties!));
        Require(properties.TryGetProperty(CreationProperty, out var marker) && marker.ValueKind == JsonValueKind.Object &&
            marker.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(["deploymentKind", "operationId", "requestDigest", "registrationDigest"]), "missing-creation-marker");
        Require(marker.GetProperty("deploymentKind").GetString() == Kind && marker.GetProperty("operationId").GetString() == operation &&
            marker.GetProperty("requestDigest").GetString() == requestDigest && marker.GetProperty("registrationDigest").GetString() == registrationDigest, "creation-marker-mismatch");
    }
    private async Task<string> UnregisterAsync(PortalClientRequest request, AdminAuditLog? registration, AdminAuditLog? terminal,
        PandaAuthDbContext db, IOpenIddictApplicationManager manager, AdminAuditWriter audit)
    {
        Require(registration is not null, "missing-registration-audit");
        var original = Record(registration!); var receipt = ReceiptJson(original); BindOriginal(request, original, receipt);
        Require(receipt.GetProperty("result").GetString() == "created" && original.RequestDigest == request["requestDigest"] &&
            receipt.GetProperty("clientId").GetString() == request.ClientId && receipt.GetProperty("registrationDigest").GetString() == request["registrationDigest"] &&
            clock.GetUtcNow() <= Utc(original.ValidUntilUtc), "rollback-binding-mismatch");
        var application = await LockedApplicationAsync(db, request.ClientId!);
        if (terminal is not null)
        {
            var previous = Record(terminal); var rollback = ReceiptJson(previous);
            Require(application is null && previous.RequestDigest == request.Digest && previous.ApplicationId == original.ApplicationId &&
                rollback.GetProperty("operationId").GetString() == request.OperationId && rollback.GetProperty("requestDigest").GetString() == original.RequestDigest &&
                rollback.GetProperty("registrationDigest").GetString() == request["registrationDigest"] &&
                rollback.GetProperty("clientId").GetString() == request.ClientId && rollback.GetProperty("result").GetString() == "unregistered", "rollback-terminal-conflict");
            return previous.ReceiptRaw;
        }
        Require(request.InWindow(clock.GetUtcNow()) && application is not null && application.Id == original.ApplicationId, "rollback-baseline-missing");
        var descriptor = await ReadMatchingAsync(manager, application!);
        Require(RegistrationDigest(descriptor) == request["registrationDigest"], "rollback-registration-mismatch");
        ValidateCreation(application!, request.OperationId, original.RequestDigest, request["registrationDigest"]);
        Require(!await db.Set<OpenIddictEntityFrameworkCoreAuthorization>().AnyAsync(a => a.Application!.Id == application!.Id) &&
            !await db.Set<OpenIddictEntityFrameworkCoreToken>().AnyAsync(t => t.Application!.Id == application!.Id), "client-has-references");
        await manager.DeleteAsync(application!);
        var raw = JsonSerializer.Serialize(new { schemaVersion = 1, deploymentKind = Kind, tenantId = "t0000", zone = "s001", machineId = "tcloud-sh-01",
            operationId = request.OperationId, requestDigest = original.RequestDigest, rollbackRequestDigest = request.Digest, clientId = request.ClientId,
            registrationDigest = request["registrationDigest"], result = "unregistered", authMetaSource = request["authMetaSource"], authServerSource = request["authServerSource"],
            planReference = request["planReference"], executionReference = request["executionReference"], executor = Executor, observedUtc = Timestamp(clock.GetUtcNow()) }) + "\n";
        await audit.RecordAsync(Entry(UnregisterAction, request, new PortalOperationRecord(request.Digest, raw, original.ApplicationId, request["validUntilUtc"])));
        return raw;
    }
}
