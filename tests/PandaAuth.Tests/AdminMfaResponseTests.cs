using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
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

    /// <summary>受操作授权门禁端点的 403 形状（AUTH-DELIVERY-002）：授权标记而非 amr step-up。</summary>
    internal static void AssertGrantRequiredResponse(IActionResult response, string operation)
    {
        var result = Assert.IsAssignableFrom<ObjectResult>(response);
        Assert.Equal(403, result.StatusCode);
        var body = JsonSerializer.SerializeToElement(result.Value);
        Assert.True(body.GetProperty("mfaGrantRequired").GetBoolean());
        Assert.Equal(operation, body.GetProperty("operation").GetString());
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
                    provider.GetRequiredService<SecurityEventWriter>(), TestGrants.Create(provider), provider.GetRequiredService<ILogger<AdminClientsController>>());
                controller = clients;
                controller.ControllerContext = new() { HttpContext = context };
                action = clients.RotateSecret("nonexistent", CancellationToken.None);
            }
            else if (operation == "user-claim")
            {
                var claims = new AdminClaimsController(provider.GetRequiredService<PandaAuthDbContext>(),
                    provider.GetRequiredService<ClaimsPolicyService>(), provider.GetRequiredService<AdminAuditWriter>(),
                    provider.GetRequiredService<SecurityEventWriter>(), TestGrants.Create(provider));
                controller = claims;
                controller.ControllerContext = new() { HttpContext = context };
                action = claims.AddUser("nonexistent", null, CancellationToken.None);
            }
            else
            {
                var users = new AdminUsersController(provider.GetRequiredService<UserService>(), provider.GetRequiredService<RoleService>(),
                    provider.GetRequiredService<SessionSecurityService>(), provider.GetRequiredService<AdminAuditWriter>(),
                    provider.GetRequiredService<SecurityEventWriter>(), TestGrants.Create(provider), provider.GetRequiredService<PandaAuthDbContext>(),
                    provider.GetRequiredService<ILogger<AdminUsersController>>());
                controller = users;
                controller.ControllerContext = new() { HttpContext = context };
                action = users.Create(null, CancellationToken.None);
            }
            // Executable cookie Forbid results redirect to AccessDenied. The BFF needs
            // a concrete API response, independently of the host's default scheme.
            // 高风险端点（轮换/claims 写）改走操作授权门禁：403 形状是授权标记；
            // 普通写（建号）仍是 amr step-up 标记。
            if (operation is "client-secret" or "user-claim")
            {
                AssertGrantRequiredResponse(await action,
                    operation == "client-secret"
                        ? MfaOperations.AdminRotateSecret
                        : MfaOperations.AdminAddUserClaim);
            }
            else
            {
                AssertStepUpResponse(await action);
            }
            Assert.Empty(revoker.RevokedUsers);
            Assert.Empty(revoker.RevokedClients);
        }
    }
}
