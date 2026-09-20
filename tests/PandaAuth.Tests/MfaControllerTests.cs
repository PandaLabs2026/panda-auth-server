using System.Security.Claims;
using Fido2NetLib;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class MfaControllerTests
{
    [Fact]
    public async Task Index_NonAdministrator_IsForbiddenBeforeAnyPasskeyCeremony()
    {
        using var provider = TestUserStoreHost.Create();
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "member" };
        await users.CreateAsync(user, "Strong!Pass123");
        var context = new DefaultHttpContext { RequestServices = provider };
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.Id)], LoginSessionService.Scheme));
        var controller = new MfaController(
            users,
            new WebAuthnCeremonyService(new Fido2(WebAuthnRelyingParty.Create("https://auth.example.test")),
                provider.GetRequiredService<PandaAuthDbContext>(), new MfaChallengeStore(provider.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(), TimeProvider.System)),
            new TotpFactorService(provider.GetRequiredService<PandaAuthDbContext>(),
                new TotpSecretProtector(Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "v1"), TimeProvider.System),
            provider.GetRequiredService<LoginSessionService>(),
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<MfaController>())
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };

        var result = await controller.Index(null, CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
    }
}
