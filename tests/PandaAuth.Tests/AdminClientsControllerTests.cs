using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public class AdminClientsControllerTests
{
    private static (AdminClientsController Controller, ServiceProvider Provider) Create()
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new AdminClientsController(
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<IOpenIddictApplicationManager>(),
            provider.GetRequiredService<AdminAuditWriter>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<AdminClientsController>())
        {
            ControllerContext = new() { HttpContext = AdminTestHost.HttpContext(provider) },
        };
        return (controller, provider);
    }

    private static async Task SeedConfidentialClientAsync(
        IOpenIddictApplicationManager applications,
        string clientId,
        string secret = "seed-secret",
        string[]? redirectUris = null,
        string[]? permissions = null,
        string[]? requirements = null)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = ClientTypes.Confidential,
            ClientSecret = secret,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = $"客户端 {clientId}",
        };
        // Permissions 是只读集合属性，只能逐项添加（对象初始化器不支持「?? 再赋值」）。
        foreach (var permission in permissions ?? [Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code])
        {
            descriptor.Permissions.Add(permission);
        }
        foreach (var uri in redirectUris ?? ["https://app.example/callback"])
        {
            descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        foreach (var requirement in requirements ?? [])
        {
            descriptor.Requirements.Add(requirement);
        }

        await applications.CreateAsync(descriptor);
    }

    [Fact]
    public async Task List_ReturnsAllClientsPaged()
    {
        var (controller, provider) = Create();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedConfidentialClientAsync(applications, "alpha");
        await SeedConfidentialClientAsync(applications, "beta");

        var ok = Assert.IsType<OkObjectResult>(await controller.List(null, null, CancellationToken.None));
        var page = Assert.IsType<AdminPageResult<AdminClientSummary>>(ok.Value);
        Assert.Equal(2, page.Total);
        Assert.Equal(["alpha", "beta"], page.Items.Select(item => item.ClientId).ToArray());
    }

    [Fact]
    public async Task Detail_ReturnsUrisPermissionsRequirements()
    {
        var (controller, provider) = Create();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedConfidentialClientAsync(applications, "gamma",
            redirectUris: ["https://gamma.example/callback"],
            permissions: [Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code, Permissions.Scopes.Roles],
            requirements: [Requirements.Features.ProofKeyForCodeExchange]);

        var ok = Assert.IsType<OkObjectResult>(await controller.Detail("gamma"));
        var detail = Assert.IsType<AdminClientDetail>(ok.Value);
        Assert.Equal(ClientTypes.Confidential, detail.ClientType);
        Assert.Equal(["https://gamma.example/callback"], detail.RedirectUris);
        Assert.Contains(Permissions.Scopes.Roles, detail.Permissions);
        Assert.Contains(Requirements.Features.ProofKeyForCodeExchange, detail.Requirements);
    }

    [Fact]
    public async Task UpdateRedirectUris_ReplacesWhitelistAndWritesAudit()
    {
        var (controller, provider) = Create();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedConfidentialClientAsync(applications, "delta", redirectUris: ["https://old.example/callback"]);

        var request = new AdminRedirectUrisRequest(
            ["https://new.example/callback", "http://localhost:5201/callback"],
            ["https://new.example/"]);
        var ok = Assert.IsType<OkObjectResult>(await controller.UpdateRedirectUris("delta", request, CancellationToken.None));
        var detail = Assert.IsType<AdminClientDetail>(ok.Value);
        Assert.Equal(
            new[] { "https://new.example/callback", "http://localhost:5201/callback" }.OrderBy(x => x),
            detail.RedirectUris.OrderBy(x => x));
        Assert.Equal(["https://new.example/"], detail.PostLogoutRedirectUris);

        var entry = Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
        Assert.Equal(AdminAuditAction.ClientUpdateUris, entry.Action);
        Assert.Contains("https://old.example/callback", entry.Detail); // 审计记录旧值
    }

    [Fact]
    public async Task UpdateRedirectUris_RejectsEmptyOrNonHttpAbsolute()
    {
        var (controller, provider) = Create();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedConfidentialClientAsync(applications, "epsilon", redirectUris: ["https://old.example/callback"]);

        var empty = Assert.IsType<ObjectResult>(await controller.UpdateRedirectUris(
            "epsilon", new AdminRedirectUrisRequest([], []), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, empty.StatusCode);

        var relative = Assert.IsType<ObjectResult>(await controller.UpdateRedirectUris(
            "epsilon", new AdminRedirectUrisRequest(["not-a-url"], []), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, relative.StatusCode);

        // 拒绝后白名单原样保留。
        var app = await applications.FindByClientIdAsync("epsilon");
        Assert.Equal(["https://old.example/callback"], (await applications.GetRedirectUrisAsync(app!)).ToArray());
        Assert.Empty(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable());
    }

    [Fact]
    public async Task UpdatePermissions_ReplacesKnownSet_RejectsUnknown()
    {
        var (controller, provider) = Create();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedConfidentialClientAsync(applications, "zeta");

        var ok = Assert.IsType<OkObjectResult>(await controller.UpdatePermissions(
            "zeta",
            new AdminPermissionsRequest(
            [
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + "api",
                Requirements.Features.ProofKeyForCodeExchange,
            ]),
            CancellationToken.None));
        var detail = Assert.IsType<AdminClientDetail>(ok.Value);
        Assert.Equal(7, detail.Permissions.Count);

        // 未知权限串被拒：OpenIddict 权限串拼错不会报错、只会静默失效，allowlist 是唯一防线。
        var rejected = Assert.IsType<ObjectResult>(await controller.UpdatePermissions(
            "zeta", new AdminPermissionsRequest(["gt:password"]), CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, rejected.StatusCode);

        var app = await applications.FindByClientIdAsync("zeta");
        Assert.DoesNotContain("gt:password", (await applications.GetPermissionsAsync(app!)).ToArray());
        Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable()); // 只有成功那次落审计
    }

    [Fact]
    public async Task RotateSecret_ReturnsPlaintextOnce_OldSecretRejected()
    {
        var (controller, provider) = Create();
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedConfidentialClientAsync(applications, "eta", secret: "original-secret");

        var ok = Assert.IsType<OkObjectResult>(await controller.RotateSecret("eta", CancellationToken.None));
        var response = Assert.IsType<AdminRotateSecretResponse>(ok.Value);
        Assert.NotEqual("original-secret", response.ClientSecret);

        var app = (await applications.FindByClientIdAsync("eta"))!;
        Assert.True(await applications.ValidateClientSecretAsync(app, response.ClientSecret));
        Assert.False(await applications.ValidateClientSecretAsync(app, "original-secret"));
        // 明文绝不入库：ClientSecret 列存的是哈希。
        var stored = provider.GetRequiredService<PandaAuthDbContext>()
            .Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>()
            .AsEnumerable().Single(entity => entity.ClientId == "eta").ClientSecret;
        Assert.NotEqual(response.ClientSecret, stored);
        Assert.Equal(AdminAuditAction.ClientRotateSecret,
            Assert.Single(provider.GetRequiredService<PandaAuthDbContext>().AdminAuditLogs.AsEnumerable()).Action);
    }

    [Fact]
    public async Task RotateSecret_RejectsPublicClient()
    {
        var (controller, provider) = Create();
        await provider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "theta",
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            Permissions = { Permissions.GrantTypes.AuthorizationCode, Permissions.ResponseTypes.Code, Requirements.Features.ProofKeyForCodeExchange },
        });

        var problem = Assert.IsType<ObjectResult>(await controller.RotateSecret("theta", CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.StatusCode);
    }
}
