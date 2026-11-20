using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

internal static class PandaMadeProductRegistration
{
    private static readonly Uri DevelopmentOrigin = new("http://127.0.0.1:5091/");

    internal static void Validate(AuthOptions options)
    {
        var seed = options.Seed.PandamadeProduct;
        if (!seed.Enabled) return;
        if (options.Issuer != PandaMadeScopes.CloudIssuer || !IsSecret(seed.WebClientSecret) ||
            !IsSecret(seed.ApiClientSecret) || seed.WebClientSecret == seed.ApiClientSecret)
            throw new InvalidOperationException("PANDAMADE_PRODUCT_REGISTRATION_INVALID");
    }

    internal static async Task SeedAsync(PandaAuthDbContext db, IOpenIddictApplicationManager applications,
        IOpenIddictScopeManager scopes, PandaMadeProductSeedOptions seed)
    {
        await using var transaction = db.Database.IsRelational() ? await db.Database.BeginTransactionAsync() : null;
        if (transaction is not null)
            await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(hashtext('pandamade-product-registration'))");

        var scope = await scopes.FindByNameAsync(PandaMadeScopes.ProductAccount);
        if (scope is not null)
        {
            var descriptor = new OpenIddictScopeDescriptor();
            await scopes.PopulateAsync(descriptor, scope);
            if (!descriptor.Resources.SetEquals([PandaMadeScopes.ProductApi]) || descriptor.Properties.Count != 0)
                throw new InvalidOperationException("PANDAMADE_PRODUCT_SCOPE_DRIFT");
        }

        var expectedWeb = new OpenIddictApplicationDescriptor
        {
            ClientId = PandaMadeScopes.ProductWebClient,
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "PandaMade Website (development)",
            ClientSecret = seed.WebClientSecret,
            RedirectUris = { new Uri(DevelopmentOrigin, new Uri(PandaMadeScopes.ProductSignInCallback).AbsolutePath) },
            PostLogoutRedirectUris = { new Uri(DevelopmentOrigin, new Uri(PandaMadeScopes.ProductSignOutCallback).AbsolutePath) },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,
                Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                Permissions.Prefixes.Scope + PandaMadeScopes.ProductAccount,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        };
        var expectedApi = new OpenIddictApplicationDescriptor
        {
            ClientId = PandaMadeScopes.ProductApi,
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "PandaMade Product API introspection",
            ClientSecret = seed.ApiClientSecret,
            Permissions = { Permissions.Endpoints.Introspection },
        };
        var hasWeb = await FindMatchingApplicationAsync(applications, expectedWeb);
        var hasApi = await FindMatchingApplicationAsync(applications, expectedApi);

        if (scope is null)
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = PandaMadeScopes.ProductAccount,
                DisplayName = "Use a PandaMade product account",
                Resources = { PandaMadeScopes.ProductApi },
            });
        if (!hasWeb) await applications.CreateAsync(expectedWeb);
        if (!hasApi) await applications.CreateAsync(expectedApi);
        if (transaction is not null) await transaction.CommitAsync();
    }

    private static bool IsSecret(string? value) => value is { Length: >= 32 } && !string.IsNullOrWhiteSpace(value);

    private static async Task<bool> FindMatchingApplicationAsync(IOpenIddictApplicationManager applications,
        OpenIddictApplicationDescriptor expected)
    {
        var existing = await applications.FindByClientIdAsync(expected.ClientId!);
        if (existing is null) return false;

        var actual = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(actual, existing);
        if (actual.ApplicationType != expected.ApplicationType || actual.ClientType != expected.ClientType ||
            actual.ConsentType != expected.ConsentType || !actual.Permissions.SetEquals(expected.Permissions) ||
            !actual.Requirements.SetEquals(expected.Requirements) ||
            !(await applications.GetRedirectUrisAsync(existing)).ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected.RedirectUris.Select(uri => uri.AbsoluteUri)) ||
            !(await applications.GetPostLogoutRedirectUrisAsync(existing)).ToHashSet(StringComparer.Ordinal)
                .SetEquals(expected.PostLogoutRedirectUris.Select(uri => uri.AbsoluteUri)) || actual.Properties.Count != 0 ||
            actual.Settings.Count != 0 || actual.JsonWebKeySet is not null ||
            !await applications.ValidateClientSecretAsync(existing, expected.ClientSecret!))
            throw new InvalidOperationException("PANDAMADE_PRODUCT_CLIENT_DRIFT");
        return true;
    }
}
