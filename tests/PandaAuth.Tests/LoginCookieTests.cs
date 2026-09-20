using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public class LoginCookieTests
{
    [Fact]
    public async Task RealCookieRoundTrip_RejectsLegacyCookieName_AndPasswordResetInvalidatesTicket()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "alice" };
        await users.CreateAsync(user, "Strong!Pass123");
        var cookie = await IssueAsync(provider, user);

        Assert.StartsWith("PandaAuth.Login.v2=", cookie);
        using (var scope = provider.CreateScope())
        {
            var context = Context(scope.ServiceProvider, cookie);
            var result = await context.AuthenticateAsync(LoginSessionService.Scheme);
            Assert.True(result.Succeeded);
            Assert.Equal(user.Id, result.Principal!.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)!.Value);
        }
        using (var scope = provider.CreateScope())
        {
            var legacy = Context(scope.ServiceProvider, cookie.Replace("PandaAuth.Login.v2=", "PandaAuth.Login="));
            Assert.False((await legacy.AuthenticateAsync(LoginSessionService.Scheme)).Succeeded);
        }
        await users.ReplacePasswordAsync(user, "Changed!Pass123");
        using (var scope = provider.CreateScope())
        {
            var context = Context(scope.ServiceProvider, cookie);
            Assert.False((await context.AuthenticateAsync(LoginSessionService.Scheme)).Succeeded);
        }
    }

    [Theory]
    [InlineData(UserStatus.Frozen)]
    [InlineData(UserStatus.Deleted)]
    public async Task NonActiveAccountCannotReuseExistingCookie(UserStatus status)
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "alice" };
        await users.CreateAsync(user, "Strong!Pass123");
        var cookie = await IssueAsync(provider, user);
        user.Status = status;
        await users.UpdateAsync(user);
        using var scope = provider.CreateScope();
        Assert.False((await Context(scope.ServiceProvider, cookie).AuthenticateAsync(LoginSessionService.Scheme)).Succeeded);
    }

    [Fact]
    public async Task MarkMfaAsync_ReissuesTicketWithWebAuthnMethodAndTimestamp()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "alice" };
        await users.CreateAsync(user, "Strong!Pass123");
        var cookie = await IssueAsync(provider, user);

        using var scope = provider.CreateScope();
        var context = Context(scope.ServiceProvider, cookie);
        Assert.True((await context.AuthenticateAsync(LoginSessionService.Scheme)).Succeeded);
        await scope.ServiceProvider.GetRequiredService<LoginSessionService>()
            .MarkMfaAsync(context, MfaClaimTypes.WebAuthn);
        var renewedCookie = context.Response.Headers.SetCookie.Single()!.Split(';')[0];

        using var verificationScope = provider.CreateScope();
        var verification = await Context(verificationScope.ServiceProvider, renewedCookie)
            .AuthenticateAsync(LoginSessionService.Scheme);
        Assert.Equal(MfaClaimTypes.WebAuthn, verification.Principal!.FindFirst(MfaClaimTypes.Method)!.Value);
        Assert.True(long.TryParse(verification.Principal.FindFirst(MfaClaimTypes.VerifiedAt)!.Value, out _));
    }

    private static async Task<string> IssueAsync(ServiceProvider provider, PandaUser user)
    {
        using var scope = provider.CreateScope();
        var context = Context(scope.ServiceProvider);
        await scope.ServiceProvider.GetRequiredService<LoginSessionService>().SignInAsync(context, user, false);
        return context.Response.Headers.SetCookie.Single()!.Split(';')[0];
    }

    private static DefaultHttpContext Context(IServiceProvider provider, string? cookie = null)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Path = "/connect/authorize";
        if (cookie is not null) context.Request.Headers.Cookie = cookie;
        return context;
    }
}
