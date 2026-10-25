using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SecurityStampRaceTests
{
    [Fact]
    public async Task RotationDuringPendingValidation_CannotRestoreAcceptanceOfOldCookie()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "stamp-race" };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        var oldStamp = user.SecurityStamp!;
        var reader = new PausedReader(provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<IPasswordHasher>());
        var pending = LoginSessionService.ValidateCookieAsync(Context(provider, user.Id, oldStamp), reader);
        await reader.ReadDone.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            Assert.True((await users.UpdateSecurityStampAsync(user)).Succeeded);
        }
        finally { reader.Resume.TrySetResult(); }
        await pending;

        // A check begun after the committed rotation must not reuse A's old snapshot.
        var next = Context(provider, user.Id, oldStamp);
        await LoginSessionService.ValidateCookieAsync(next, users);
        Assert.Null(next.Principal);
    }

    private static CookieValidatePrincipalContext Context(IServiceProvider provider, string id, string stamp)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, id), new Claim(LoginSessionService.StampClaim, stamp),
            new Claim(PandaAuthClaims.SecurityVersion, AccountSecurityVersion.From(new PandaUser { Id = id, SecurityStamp = stamp })),
            new Claim(PandaAuthClaims.SsoSessionId, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        }, LoginSessionService.Scheme));
        return new(new DefaultHttpContext { RequestServices = provider },
            new AuthenticationScheme(LoginSessionService.Scheme, null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(), new AuthenticationTicket(principal, LoginSessionService.Scheme));
    }

    private sealed class PausedReader(PandaAuthDbContext db, IPasswordHasher hasher)
        : UserService(db, hasher, TimeProvider.System)
    {
        public TaskCompletionSource ReadDone { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async Task<PandaUser?> FindByIdAsync(string id)
        {
            var snapshot = await base.FindByIdAsync(id);
            ReadDone.TrySetResult();
            await Resume.Task.WaitAsync(TimeSpan.FromSeconds(10));
            return snapshot;
        }
    }
}
