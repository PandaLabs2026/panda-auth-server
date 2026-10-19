using System.Security.Claims;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.SessionState;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SessionStateAuthorizationTests
{
    [Fact]
    public void Requires_both_session_api_audience_and_scope()
    {
        var valid = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(OpenIddictConstants.Claims.Audience, PandaAuthSessionApi.Audience),
            new Claim(OpenIddictConstants.Claims.Scope, PandaAuthSessionApi.Scope),
        ], "Bearer"));
        var missingAudience = new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim(OpenIddictConstants.Claims.Scope, PandaAuthSessionApi.Scope)], "Bearer"));
        var missingScope = new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim(OpenIddictConstants.Claims.Audience, PandaAuthSessionApi.Audience)], "Bearer"));

        Assert.True(SessionStateAuthorization.HasAudienceAndScope(valid));
        Assert.False(SessionStateAuthorization.HasAudienceAndScope(missingAudience));
        Assert.False(SessionStateAuthorization.HasAudienceAndScope(missingScope));
    }
}
