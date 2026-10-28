using System.Security.Cryptography;
using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Infrastructure.Persistence;
using static OpenIddict.Abstractions.OpenIddictConstants;
using PandaAuth.Shared;

namespace PandaAuth.ReadinessHarness;

/// <summary>Read-only account selection. Caller must establish the approved
/// runtime DB identity and a read-only transaction before invoking this probe.</summary>
internal static class ActivationIdentityPreflight
{
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static void Require(bool value) { if (!value) throw new InvalidOperationException("activation_identity_preflight_failed"); }

    internal static NpgsqlConnectionStringBuilder Connection(ActivationHumanInput input)
    {
        Require(input.Instance is "fleet" or "t0000" && !string.IsNullOrEmpty(input.RuntimeConnection));
        var result = new NpgsqlConnectionStringBuilder(input.RuntimeConnection);
        var database = "panda_auth_" + input.Instance;
        var host = input.Instance == "fleet" ? "127.0.0.1" : "pandalabs-postgres";
        Require(result.Host == host && result.Port == 5432 && result.Database == database
            && result.Username == database + "_runtime" && !string.IsNullOrEmpty(result.Password)
            && string.IsNullOrEmpty(result.Options));
        result.Pooling = false;
        result.Timeout = 10;
        result.CommandTimeout = 30;
        result.SearchPath = "pg_catalog, public";
        return result;
    }

    internal static async Task CheckDatabaseAsync(ActivationHumanInput input, Action checkpoint, CancellationToken cancellation = default)
    {
        var settings = Connection(input);
        checkpoint();
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellation);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellation);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction))
            await readOnly.ExecuteNonQueryAsync(cancellation);
        await using (var command = new NpgsqlCommand("SELECT current_user, session_user, current_database(), (SELECT oid::text FROM pg_catalog.pg_database WHERE datname=current_database())", connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(cancellation))
        {
            Require(await reader.ReadAsync(cancellation));
            var user = reader.GetString(0); var sessionUser = reader.GetString(1); var database = reader.GetString(2); var oid = reader.GetString(3);
            var fingerprint = Hash(string.Join('\0', settings.Host!.ToLowerInvariant(), settings.Port.ToString(CultureInfo.InvariantCulture), database, oid));
            Require(user == settings.Username && sessionUser == settings.Username && database == settings.Database && fingerprint == input.DatabaseFingerprint
                && !await reader.ReadAsync(cancellation));
        }
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(connection).UseOpenIddict().Options);
        await db.Database.UseTransactionAsync(transaction, cancellation);
        checkpoint();
        await CheckClientAsync(db, input.Component, input.Issuer, input.RedirectUri, cancellation);
        await CheckClientSecretAsync(db, input.ClientId, input.ClientSecret, cancellation);
        await CheckAsync(db, input.Identity.UserName, input.Identity.UsernameSha256, input.Identity.SubjectSha256,
            input.Component == "admin", DateTimeOffset.UtcNow, cancellation);
        if (input.Component == "admin")
        {
            Require(input.Restricted is not null);
            await CheckAsync(db, input.Restricted!.UserName, input.Restricted.UsernameSha256, input.Restricted.SubjectSha256,
                false, DateTimeOffset.UtcNow, cancellation);
        }
        checkpoint();
        await transaction.CommitAsync(cancellation);
    }

    internal static async Task<bool> CheckClientAsync(PandaAuthDbContext db, string component, string issuer,
        string redirectUri, CancellationToken cancellation = default)
    {
        Require(component is "admin" or "me" && Uri.TryCreate(issuer, UriKind.Absolute, out var owner)
            && owner.Scheme == "https" && owner.UserInfo.Length == 0 && owner.AbsolutePath == "/"
            && owner.Query.Length == 0 && owner.Fragment.Length == 0);
        Require(Uri.TryCreate(redirectUri, UriKind.Absolute, out var callback) && callback.Scheme == "https"
            && callback.GetLeftPart(UriPartial.Authority) == new Uri(issuer).GetLeftPart(UriPartial.Authority)
            && callback.UserInfo.Length == 0 && callback.Query.Length == 0 && callback.Fragment.Length == 0
            && callback.AbsolutePath.StartsWith("/" + component + "/callback/", StringComparison.Ordinal));
        var clientId = component == "admin" ? FirstPartyClients.AdminWeb : FirstPartyClients.MeWeb;
        var matches = await db.Set<OpenIddictEntityFrameworkCoreApplication>().AsNoTracking().Where(app => app.ClientId == clientId)
            .Select(app => new { app.ClientId, app.ClientType, HasSecret = app.ClientSecret != null && app.ClientSecret != "",
                Permissions = app.Permissions != null && app.Permissions.Length <= 65536 ? app.Permissions : null,
                RedirectUris = app.RedirectUris != null && app.RedirectUris.Length <= 65536 ? app.RedirectUris : null })
            .Take(2).ToListAsync(cancellation);
        Require(matches.Count == 1 && matches[0].ClientId == clientId && matches[0].ClientType == ClientTypes.Confidential && matches[0].HasSecret);
        var permissions = Array(matches[0].Permissions);
        var redirects = Array(matches[0].RedirectUris);
        string[] required = [Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Revocation, Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code, Permissions.Scopes.Email, Permissions.Scopes.Profile, Permissions.Scopes.Roles];
        Require(required.All(permissions.Contains) && redirects.Contains(redirectUri));
        var adminScope = Permissions.Prefixes.Scope + PandaAuthAdminApi.Scope;
        Require(component == "admin" ? permissions.Contains(adminScope) : !permissions.Contains(adminScope));
        return true;
    }

    internal static async Task<bool> CheckClientSecretAsync(PandaAuthDbContext db, string clientId,
        string clientSecret, CancellationToken cancellation = default)
    {
        Require(clientId is FirstPartyClients.AdminWeb or FirstPartyClients.MeWeb && !string.IsNullOrEmpty(clientSecret));
        // Use the same OpenIddict secret verifier as the Server. The stored
        // verifier may be loaded in this private process; it is never returned
        // or logged, and the verified read-only transaction remains in force.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(db);
        services.AddOpenIddict().AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = await manager.FindByClientIdAsync(clientId, cancellation);
        Require(application is not null && await manager.ValidateClientSecretAsync(application, clientSecret, cancellation));
        return true;
    }

    private static HashSet<string> Array(string? value)
    {
        try
        {
            Require(value is { Length: > 0 and <= 65536 });
            var entries = JsonSerializer.Deserialize<string[]>(value!);
            Require(entries is { Length: > 0 and <= 256 } && entries.All(item => item is { Length: > 0 and <= 4096 }));
            var result = new HashSet<string>(entries!, StringComparer.Ordinal);
            Require(result.Count == entries!.Length);
            return result;
        }
        catch (JsonException) { throw new InvalidOperationException("activation_identity_preflight_failed"); }
    }

    internal static async Task<bool> CheckAsync(PandaAuthDbContext db, string userName, string usernameSha256,
        string subjectSha256, bool expectAdmin, DateTimeOffset now, CancellationToken cancellation = default)
    {
        Require(userName is { Length: > 0 and <= 256 } && userName == userName.Trim() && Hash(userName) == usernameSha256);
        // This is the exact lookup normalization in UserService.FindByNameAsync.
        // Project only the facts needed here; do not load the password hash or
        // TOTP ciphertext into the helper.
        var normalized = userName.Normalize().ToUpperInvariant();
        var matches = await db.Users.AsNoTracking().Where(user => user.NormalizedUserName == normalized)
            .Select(user => new { user.Id, user.UserName, user.Status, user.EmailConfirmed, user.TwoFactorEnabled,
                user.LockoutEnabled, user.LockoutEnd, HasPassword = user.PasswordHash != null && user.PasswordHash != "" })
            .Take(2).ToListAsync(cancellation);
        Require(matches.Count == 1);
        var user = matches[0];
        Require(user.UserName == userName && Hash(user.Id) == subjectSha256 && user.Status == UserStatus.Active
            && user.EmailConfirmed && user.TwoFactorEnabled && user.HasPassword
            && (!user.LockoutEnabled || user.LockoutEnd is null || user.LockoutEnd <= now));
        var roleNames = await (from membership in db.UserRoles.AsNoTracking()
                             join role in db.Roles.AsNoTracking() on membership.RoleId equals role.Id
                             where membership.UserId == user.Id
                             select role.Name).ToListAsync(cancellation);
        // Claims authorization compares actual role names, not normalized
        // lookup keys or potentially case-insensitive database collation.
        var isAdmin = roleNames.Any(name => string.Equals(name, PandaAuthRoles.Admin, StringComparison.Ordinal));
        Require(isAdmin == expectAdmin);
        var step = now.ToUnixTimeSeconds() / 30;
        var usableFactor = await db.TotpFactors.AsNoTracking().AnyAsync(factor => factor.UserId == user.Id
            && factor.ConfirmedAt != null && factor.RevokedAt == null
            && (factor.LastAcceptedTimeStep == null || factor.LastAcceptedTimeStep <= step), cancellation);
        Require(usableFactor);
        return true;
    }
}
