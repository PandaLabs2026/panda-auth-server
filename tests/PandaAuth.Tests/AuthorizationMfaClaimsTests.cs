using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Authorization;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class AuthorizationMfaClaimsTests
{
    [Fact]
    public async Task CreatePrincipal_CopiesMfaFactsOnlyFromTrustedSource()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<PandaAuth.Server.Infrastructure.Security.UserService>();
        var user = new PandaUser { UserName = "admin" };
        await users.CreateAsync(user, "Strong!Pass123");
        var controller = TestUserStoreHost.CreateAuthorizationController(provider);
        var source = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(MfaClaimTypes.Method, MfaClaimTypes.WebAuthn),
            new Claim(MfaClaimTypes.VerifiedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        ], "trusted"));

        var principal = await controller.CreatePrincipalAsync(user, [OpenIddictConstants.Scopes.OpenId], source);

        Assert.Equal(MfaClaimTypes.WebAuthn, principal.FindFirst(MfaClaimTypes.Method)!.Value);
        Assert.NotNull(principal.FindFirst(MfaClaimTypes.VerifiedAt));
    }
}
