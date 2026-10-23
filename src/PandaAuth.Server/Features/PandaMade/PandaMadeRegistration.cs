using OpenIddict.Abstractions;
using PandaAuth.Server.Features.PortalClients;
using Npgsql;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.PandaMade;

internal static class PandaMadeRegistration
{
    public static async Task<int> MigrateAsync(IConfiguration configuration, string environment, TextWriter output, TextWriter error)
    {
        try
        {
            if (environment != "Production") throw new InvalidOperationException();
            var connection = await PandaMadeProductionGuard.RequireAsync(configuration, "migrate");
            using var provider = PortalClientCommand.Services(connection);
            await using var operation = provider.CreateAsyncScope();
            await using var lease = await DatabaseLease.AcquireAsync(connection);
            var db = operation.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
            var known = db.Database.GetMigrations().ToHashSet(StringComparer.Ordinal);
            if ((await db.Database.GetAppliedMigrationsAsync()).Any(id => !known.Contains(id))) throw new InvalidOperationException();
            await db.Database.MigrateAsync();
            await output.WriteLineAsync("pandamade-migration-ok");
            return 0;
        }
        catch { await error.WriteLineAsync("pandamade-migration-closed"); return 1; }
    }

    public static async Task RegisterAsync(IServiceProvider provider, Uri origin, string adminSecret, string apiSecret)
    {
        var descriptors = Describe(origin, adminSecret, apiSecret);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = provider.GetRequiredService<IOpenIddictScopeManager>();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(hashtext('pandamade-client-registration'))");
        var currentScope = await scopes.FindByNameAsync(PandaMadeScopes.Manage);
        if (currentScope is null) await scopes.CreateAsync(descriptors.Scope);
        else
        {
            var actual = new OpenIddictScopeDescriptor(); await scopes.PopulateAsync(actual, currentScope);
            if (!actual.Resources.SetEquals(descriptors.Scope.Resources) || actual.Properties.Count != 0)
                throw new InvalidOperationException("pandamade-registration-conflict");
        }
        foreach (var expected in new[] { descriptors.Admin, descriptors.Api })
        {
            var existing = await applications.FindByClientIdAsync(expected.ClientId!);
            if (existing is null) { await applications.CreateAsync(expected); continue; }
            var actual = new OpenIddictApplicationDescriptor(); await applications.PopulateAsync(actual, existing);
            if (actual.ClientType != expected.ClientType || actual.ConsentType != expected.ConsentType ||
                !actual.RedirectUris.SetEquals(expected.RedirectUris) || !actual.PostLogoutRedirectUris.SetEquals(expected.PostLogoutRedirectUris) ||
                !actual.Permissions.SetEquals(expected.Permissions) || !actual.Requirements.SetEquals(expected.Requirements) ||
                actual.Properties.Count != 0 || actual.Settings.Count != 0 || actual.JsonWebKeySet is not null ||
                !await applications.ValidateClientSecretAsync(existing, expected.ClientSecret!))
                throw new InvalidOperationException("pandamade-registration-conflict");
        }
        await transaction.CommitAsync();
    }

    public static (OpenIddictScopeDescriptor Scope, OpenIddictApplicationDescriptor Admin, OpenIddictApplicationDescriptor Api)
        Describe(Uri adminOrigin, string adminSecret, string apiSecret)
    {
        if (adminOrigin.Scheme != "https" || adminOrigin.AbsolutePath != "/" ||
            adminOrigin.UserInfo.Length != 0 || adminOrigin.Query.Length != 0 || adminOrigin.Fragment.Length != 0 ||
            string.IsNullOrWhiteSpace(adminSecret) || adminSecret.Length < 32 ||
            string.IsNullOrWhiteSpace(apiSecret) || apiSecret.Length < 32 || adminSecret == apiSecret)
            throw new InvalidOperationException("pandamade-registration-invalid");
        var scope = new OpenIddictScopeDescriptor { Name = PandaMadeScopes.Manage, DisplayName = "Manage PandaMade catalog" };
        scope.Resources.Add(PandaMadeScopes.Api);
        var admin = new OpenIddictApplicationDescriptor
        {
            ClientId = PandaMadeScopes.AdminClient, ClientType = ClientTypes.Confidential,
            ClientSecret = adminSecret, ConsentType = ConsentTypes.Implicit, DisplayName = "PandaMade Admin",
            RedirectUris = { new Uri(adminOrigin, "signin-oidc") },
            PostLogoutRedirectUris = { new Uri(adminOrigin, "signout-callback-oidc") },
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession, Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code, Permissions.Scopes.Profile,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess, Permissions.Prefixes.Scope + PandaMadeScopes.Manage },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        };
        var api = new OpenIddictApplicationDescriptor
        {
            ClientId = PandaMadeScopes.Api, ClientType = ClientTypes.Confidential, ClientSecret = apiSecret,
            ConsentType = ConsentTypes.Implicit, DisplayName = "PandaMade API introspection",
            Permissions = { Permissions.Endpoints.Introspection },
        };
        return (scope, admin, api);
    }
}
