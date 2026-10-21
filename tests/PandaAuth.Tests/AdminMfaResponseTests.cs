using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public class AdminMfaResponseTests
{
    internal static void AssertStepUpResponse(IActionResult response)
    {
        var result = Assert.IsAssignableFrom<ObjectResult>(response);
        Assert.Equal(403, result.StatusCode);
        Assert.True(JsonSerializer.SerializeToElement(result.Value).GetProperty("mfaRequired").GetBoolean());
    }

    [Theory]
    [InlineData("client-secret")]
    [InlineData("user-claim")]
    [InlineData("create-user")]
    public async Task MissingMfa_ReturnsExplicitForbiddenWithStepUpMarker(string operation)
    {
        var (provider, revoker) = AdminTestHost.Create();
        using (provider)
        {
            var context = AdminTestHost.HttpContext(provider);
            context.User = AdminTestHost.AdminPrincipalWithoutMfa();
            Controller controller;
            Task<IActionResult> action;
            if (operation == "client-secret")
            {
                var clients = new AdminClientsController(provider.GetRequiredService<PandaAuthDbContext>(),
                    provider.GetRequiredService<IOpenIddictApplicationManager>(), provider.GetRequiredService<AdminAuditWriter>(),
                    provider.GetRequiredService<SecurityEventWriter>(), provider.GetRequiredService<ILogger<AdminClientsController>>());
                controller = clients;
                controller.ControllerContext = new() { HttpContext = context };
                action = clients.RotateSecret("nonexistent", CancellationToken.None);
            }
            else if (operation == "user-claim")
            {
                var claims = new AdminClaimsController(provider.GetRequiredService<PandaAuthDbContext>(),
                    provider.GetRequiredService<ClaimsPolicyService>(), provider.GetRequiredService<AdminAuditWriter>(),
                    provider.GetRequiredService<SecurityEventWriter>());
                controller = claims;
                controller.ControllerContext = new() { HttpContext = context };
                action = claims.AddUser("nonexistent", null, CancellationToken.None);
            }
            else
            {
                var users = new AdminUsersController(provider.GetRequiredService<UserService>(), provider.GetRequiredService<RoleService>(),
                    provider.GetRequiredService<SessionSecurityService>(), provider.GetRequiredService<AdminAuditWriter>(),
                    provider.GetRequiredService<SecurityEventWriter>(), provider.GetRequiredService<PandaAuthDbContext>(),
                    provider.GetRequiredService<ILogger<AdminUsersController>>());
                controller = users;
                controller.ControllerContext = new() { HttpContext = context };
                action = users.Create(null, CancellationToken.None);
            }
            // Executable cookie Forbid results redirect to AccessDenied. The BFF needs
            // a concrete API response, independently of the host's default scheme.
            AssertStepUpResponse(await action);
            Assert.Empty(revoker.RevokedUsers);
            Assert.Empty(revoker.RevokedClients);
        }
    }
}
