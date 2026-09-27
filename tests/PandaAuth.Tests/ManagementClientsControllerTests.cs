using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Management;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// Management API 客户端 CRUD（M0 S3）聚焦测试：直接调用控制器（授权语义单测见 MgmtApiAuthorizationTests）。
/// 审计断言覆盖 mgmt.client.* 前缀与 M2M 主体（ActorUserId = 调用方 clientId）。
/// </summary>
public class ManagementClientsControllerTests
{
    private static (ManagementClientsController Controller, ServiceProvider Provider, PandaAuthDbContext DbContext) Create()
    {
        var (provider, _) = AdminTestHost.Create();
        var controller = new ManagementClientsController(
            provider.GetRequiredService<PandaAuthDbContext>(),
            provider.GetRequiredService<IOpenIddictApplicationManager>(),
            provider.GetRequiredService<AdminAuditWriter>(),
            TestsMgmtLimiter.New(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger<ManagementClientsController>())
        {
            ControllerContext = new() { HttpContext = MgmtHttpContext(provider) },
        };
        return (controller, provider, provider.GetRequiredService<PandaAuthDbContext>());
    }

    /// <summary>client credentials 主体等价物：OpenIddict 签发的 M2M 令牌 sub = clientId。</summary>
    private static DefaultHttpContext MgmtHttpContext(IServiceProvider provider, string clientId = "mgmt-api")
        => new()
        {
            RequestServices = provider,
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(Claims.Subject, clientId),
                new Claim(Claims.ClientId, clientId),
            ], OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)),
            Connection = { RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.10") },
        };

    private static ManagementCreateClientRequest CreateRequest(
        string? clientId = null, string? clientType = "confidential", string? displayName = "测试客户端")
        => new(
            DisplayName: displayName!,
            ClientType: clientType,
            ClientId: clientId,
            RedirectUris: ["https://app.example.com/callback/login/pandaauth"],
            PostLogoutRedirectUris: ["https://app.example.com/"]);

    private static AdminClientDetail DetailOf(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return Assert.IsType<AdminClientDetail>(ok.Value);
    }

    private static ProblemDetails ProblemOf(IActionResult result)
        => Assert.IsType<ObjectResult>(result).Value as ProblemDetails
           ?? throw new Xunit.Sdk.XunitException("响应不是 ProblemDetails");

    [Fact]
    public async Task Create_Confidential_ReturnsSecretOnceAndPersistsHash()
    {
        var (controller, provider, _) = Create();

        var ok = Assert.IsType<OkObjectResult>(await controller.Create(CreateRequest(clientId: "app-a"), CancellationToken.None));
        var response = Assert.IsType<ManagementCreateClientResponse>(ok.Value);

        Assert.False(string.IsNullOrWhiteSpace(response.GeneratedSecret));
        Assert.Equal("app-a", response.Client.ClientId);
        Assert.Equal(ClientTypes.Confidential, response.Client.ClientType);
        Assert.Contains(Requirements.Features.ProofKeyForCodeExchange, response.Client.Requirements);

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await applications.FindByClientIdAsync("app-a");
        Assert.NotNull(app);
        Assert.True(await applications.ValidateClientSecretAsync(app, response.GeneratedSecret));
    }

    [Fact]
    public async Task Create_Public_HasNoSecretButKeepsPkce()
    {
        var (controller, _, _) = Create();

        var ok = Assert.IsType<OkObjectResult>(await controller.Create(CreateRequest(clientId: "app-p", clientType: "public"), CancellationToken.None));
        var response = Assert.IsType<ManagementCreateClientResponse>(ok.Value);

        Assert.Null(response.GeneratedSecret);
        Assert.Equal(ClientTypes.Public, response.Client.ClientType);
        Assert.Contains(Requirements.Features.ProofKeyForCodeExchange, response.Client.Requirements);
    }

    [Fact]
    public async Task Create_ValidationFailures_Return400()
    {
        var (controller, _, _) = Create();

        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.Create(CreateRequest(displayName: ""), CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.Create(CreateRequest(clientId: "非法*id"), CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.Create(CreateRequest() with { RedirectUris = [] }, CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.Create(CreateRequest() with { RedirectUris = ["not-a-uri"] }, CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.Create(CreateRequest(clientType: "weird"), CancellationToken.None)).StatusCode);
    }

    [Fact]
    public async Task Create_DuplicateOrReservedClientId_409()
    {
        var (controller, _, _) = Create();

        Assert.IsType<OkObjectResult>(await controller.Create(CreateRequest(clientId: "app-dup"), CancellationToken.None));
        Assert.Equal(StatusCodes.Status409Conflict,
            ((ObjectResult)await controller.Create(CreateRequest(clientId: "app-dup"), CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status409Conflict,
            ((ObjectResult)await controller.Create(CreateRequest(clientId: "mgmt-api"), CancellationToken.None)).StatusCode);
    }

    [Fact]
    public async Task Update_AppliesProvidedFieldsOnlyAndAudits()
    {
        var (controller, _, dbContext) = Create();
        var created = Assert.IsType<ManagementCreateClientResponse>(
            (Assert.IsType<OkObjectResult>(await controller.Create(CreateRequest(clientId: "app-u"), CancellationToken.None))).Value).Client;

        var updated = DetailOf(await controller.Update("app-u",
            new ManagementUpdateClientRequest(
                DisplayName: "新显示名",
                RedirectUris: ["https://app.example.com/callback/v2"],
                PostLogoutRedirectUris: null),
            CancellationToken.None));

        Assert.Equal("新显示名", updated.DisplayName);
        Assert.Equal(["https://app.example.com/callback/v2"], updated.RedirectUris);
        // 未提供的字段保持不变。
        Assert.Equal(created.PostLogoutRedirectUris, updated.PostLogoutRedirectUris);

        var entry = dbContext.AdminAuditLogs.Single(a => a.Action == "mgmt.client.update");
        Assert.Equal("mgmt-api", entry.ActorUserId);
        Assert.Equal("app-u", entry.TargetId);
        Assert.Contains("previousRedirectUris", entry.Detail);
    }

    [Fact]
    public async Task Update_EmptyRedirectUris_400()
    {
        var (controller, _, _) = Create();
        await controller.Create(CreateRequest(clientId: "app-u2"), CancellationToken.None);

        var problem = ProblemOf(await controller.Update("app-u2",
            new ManagementUpdateClientRequest(null, [], null), CancellationToken.None));

        Assert.Equal(StatusCodes.Status400BadRequest, problem.Status);
        Assert.Contains("回调白名单不能为空", problem.Title);
    }

    [Fact]
    public async Task ReservedClients_ReadOnlyThroughManagementApi()
    {
        var (controller, _, _) = Create();

        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.Update("mgmt-api", new ManagementUpdateClientRequest("x", null, null), CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.ResetSecret("admin-web", CancellationToken.None)).StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest,
            ((ObjectResult)await controller.Delete("me-web", CancellationToken.None)).StatusCode);
    }

    [Fact]
    public async Task ResetSecret_OldSecretInvalidatesAndAuditRecords()
    {
        var (controller, provider, dbContext) = Create();
        var created = Assert.IsType<ManagementCreateClientResponse>(
            (Assert.IsType<OkObjectResult>(await controller.Create(CreateRequest(clientId: "app-r"), CancellationToken.None))).Value);

        var ok = Assert.IsType<OkObjectResult>(await controller.ResetSecret("app-r", CancellationToken.None));
        var rotated = Assert.IsType<AdminRotateSecretResponse>(ok.Value);
        Assert.NotNull(rotated.ClientSecret);

        Assert.NotEqual(created.GeneratedSecret, rotated.ClientSecret);
        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = (await applications.FindByClientIdAsync("app-r"))!;
        Assert.False(await applications.ValidateClientSecretAsync(app, created.GeneratedSecret!));
        Assert.True(await applications.ValidateClientSecretAsync(app, rotated.ClientSecret));
        Assert.NotNull(dbContext.AdminAuditLogs.Single(a => a.Action == "mgmt.client.rotate_secret"));
    }

    [Fact]
    public async Task ResetSecret_PublicClient_400()
    {
        var (controller, _, _) = Create();
        await controller.Create(CreateRequest(clientId: "app-pub", clientType: "public"), CancellationToken.None);

        var problem = ProblemOf(await controller.ResetSecret("app-pub", CancellationToken.None));
        Assert.Equal(StatusCodes.Status400BadRequest, problem.Status);
    }

    // OpenIddict 7 的 DeleteAsync 内部使用 ExecuteDeleteAsync，EF InMemory 提供程序不支持；
    // 删除持久化与审计断言随 S5 在隔离 PostgreSQL 的 e2e 覆盖（生产 Npgsql 支持该语句）。
    [Fact(Skip = "InMemory 提供程序不支持 ExecuteDeleteAsync；删除路径由 S5 隔离 PostgreSQL e2e 覆盖")]
    public async Task Delete_RemovesClientAndAudits()
    {
        var (controller, provider, dbContext) = Create();
        await controller.Create(CreateRequest(clientId: "app-del"), CancellationToken.None);

        Assert.IsType<NoContentResult>(await controller.Delete("app-del", CancellationToken.None));

        var applications = provider.GetRequiredService<IOpenIddictApplicationManager>();
        Assert.Null(await applications.FindByClientIdAsync("app-del"));
        var entry = dbContext.AdminAuditLogs.Single(a => a.Action == "mgmt.client.delete");
        Assert.Equal("app-del", entry.TargetId);
    }

    [Fact]
    public async Task Delete_UnknownClient_404()
    {
        var (controller, _, _) = Create();

        Assert.IsType<NotFoundResult>(await controller.Delete("ghost", CancellationToken.None));
        Assert.IsType<NotFoundResult>(await controller.Detail("ghost"));
    }

    [Fact]
    public async Task List_Paginates()
    {
        var (controller, _, _) = Create();
        await controller.Create(CreateRequest(clientId: "app-l1"), CancellationToken.None);
        await controller.Create(CreateRequest(clientId: "app-l2"), CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(await controller.List(null, null, CancellationToken.None));
        var page = Assert.IsType<AdminPageResult<AdminClientSummary>>(ok.Value);

        Assert.Equal(2, page.Total);
        Assert.Equal(["app-l1", "app-l2"], [.. page.Items.Select(item => item.ClientId)]);
    }
}
