using System.Net;
using Fido2NetLib;
using Fido2NetLib.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using PandaAuth.Shared;

var builder = WebApplication.CreateBuilder(args);

var isMigrateCommand = args.Contains("--migrate", StringComparer.Ordinal);
var connectionStringName = isMigrateCommand ? "Migration" : "Default";
var connectionString = builder.Configuration.GetConnectionString(connectionStringName)
    ?? throw new InvalidOperationException($"缺少连接字符串 ConnectionStrings:{connectionStringName}。");

builder.Services.AddControllersWithViews()
    .AddJsonOptions(options =>
        options.JsonSerializerOptions.TypeInfoResolverChain.Insert(0, FidoModelSerializerContext.Default));

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.SectionName));
var authOptions = builder.Configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>() ?? new AuthOptions();
// 签名密钥周期误配会让旧 Access Token 在旧密钥退役后静默验签失败，必须在读取密钥表之前失败关闭。
authOptions.Keys.Validate();
authOptions.Mfa.Validate(builder.Environment.IsProduction());

builder.Services.AddDbContext<PandaAuthDbContext>(options =>
{
    options.UseNpgsql(connectionString);
    options.UseOpenIddict();
});

builder.Services.AddUserStore(authOptions.HttpsRequired);

builder.Services.AddScoped<IPasswordHasher, Argon2idPasswordHasher>();

if (authOptions.DataProtectionKeyPath.Length > 0)
{
    // 路径必须已存在：生产由 compose 命名卷挂载保证；不存在即说明「配置路径与卷挂载点不一致」，
    // 此时绝不能静默创建到容器临时层（密钥随容器重建即丢），必须失败关闭。
    // PersistKeysToFileSystem 自身会静默创建缺失目录且不告警，故守卫必须显式。
    if (!Directory.Exists(authOptions.DataProtectionKeyPath))
    {
        throw new InvalidOperationException(
            $"DataProtection 密钥目录不存在：{authOptions.DataProtectionKeyPath}（生产应由 compose 命名卷挂载到该路径）");
    }

    builder.Services
        .AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(authOptions.DataProtectionKeyPath))
        .SetApplicationName("PandaAuth");
}

// OpenIddict Core 也用于迁移后执行应用/客户端种子数据。
var openIddict = builder.Services
    .AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>());

// 一次性迁移模式：docker compose run --rm auth-server --migrate（使用独立 DDL 账号）。
if (isMigrateCommand)
{
    using var migrateApp = builder.Build();
    using var migrateScope = migrateApp.Services.CreateScope();
    await migrateScope.ServiceProvider.GetRequiredService<PandaAuthDbContext>().Database.MigrateAsync();
    await DbSeeder.SeedAsync(migrateScope.ServiceProvider);
    migrateApp.Logger.LogInformation("数据库迁移与种子数据初始化完成。");
    return;
}

// OpenIddict 要求在容器构建前注册密钥：从数据库加载（无密钥自动生成、超期自动轮换）。
var keys = await SigningKeyStore.LoadOrCreateAsync(connectionString, authOptions.Keys);

openIddict.AddServer(options =>
    {
        options
            .AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowClientCredentialsFlow()
            .AllowRefreshTokenFlow();

        // 端点路径统一取自 PandaAuth 契约常量（share 仓 PandaAuthEndpoints），避免服务端与契约双源。
        options.SetAuthorizationEndpointUris(PandaAuthEndpoints.Authorization)
            .SetTokenEndpointUris(PandaAuthEndpoints.Token)
            .SetUserInfoEndpointUris(PandaAuthEndpoints.Userinfo)
            .SetEndSessionEndpointUris(PandaAuthEndpoints.Logout)
            .SetIntrospectionEndpointUris(PandaAuthEndpoints.Introspection)
            .SetRevocationEndpointUris(PandaAuthEndpoints.Revocation)
            // JWKS 路径显式化：此前依赖 OpenIddict 默认值（同为 /.well-known/jwks），行为不变，契约成为单一事实源。
            .SetJsonWebKeySetEndpointUris(PandaAuthEndpoints.JsonWebKeySet);

        // 文档门禁：AccessToken 10 分钟；RefreshToken 可吊销。
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(10))
            .SetRefreshTokenLifetime(TimeSpan.FromDays(14))
            .SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5));

        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles,
            OpenIddictConstants.Scopes.OfflineAccess,
            "api");

        // Issuer 全部来自配置（生产 https://auth.pandalabs.cc，海外实例改环境变量即可，零代码切换）。
        options.SetIssuer(IssuerUri());

        foreach (var (record, key) in keys)
        {
            if (record.Use == KeyUse.Signing)
            {
                options.AddSigningKey(key);
            }
            else
            {
                options.AddEncryptionKey(key);
            }
        }

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough();

        if (!authOptions.HttpsRequired)
        {
            options.UseAspNetCore().DisableTransportSecurityRequirement();
        }
    })
    // 自定义 API（/admin-api/*）的 Bearer 验证用 Validation 方案，而非 Server 方案——
    // Server 方案只对它管理的端点（/connect/*，如 userinfo）提取身份，自定义端点会抛
    // 「An identity cannot be extracted from this request」（2026-09-19 生产实测）。
    // UseLocalServer：同进程导入 Server 的签名/加密凭据与配置——缺它时认证中间件惰性解析
    // options 即抛「server configuration or an issuer URI must be registered」（2026-09-19 生产实测，
    // 连 /healthz 都 500，因认证中间件对每个请求都会探测已注册的 handler）。
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Admin API 角色门禁：按 claim 短名（"role"）断言而非 Roles=——后者走 IsInRole，
// 依赖 identity 的 RoleClaimType 映射（validation 方案默认是 ASP.NET 长名 URI），会静默 403。
// 这里只做登录、邮箱确认和 admin 角色门禁；GET 只读接口不能被 MFA 阻断。
// 写操作在控制器动作内按风险分级检查：普通写操作要求八小时内任一 MFA，
// 高风险操作继续要求五分钟内 WebAuthn（见 AdminApiAuthorization）。
builder.Services.AddAuthorization(options => options.AddPolicy(AdminApiAuthorization.PolicyName, policy =>
    policy.RequireClaim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Role, PandaAuthRoles.Admin)));

// 登录限流器条目承载在内存缓存上并按 TTL 回收（见 LoginRateLimiter）。
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<IFido2>(_ => new Fido2(WebAuthnRelyingParty.Create(authOptions.Issuer)));
builder.Services.AddSingleton<MfaChallengeStore>();
builder.Services.AddScoped<WebAuthnCeremonyService>();
builder.Services.AddSingleton(serviceProvider => new TotpSecretProtector(
    authOptions.Mfa.GetEncryptionKey(builder.Environment.IsProduction()), authOptions.Mfa.TotpKeyVersion));
builder.Services.AddScoped<TotpFactorService>();
builder.Services.AddScoped<MfaService>();
builder.Services.AddSingleton<LoginRateLimiter>();
builder.Services.AddScoped<LoginAuditWriter>();
builder.Services.AddScoped<AdminAuditWriter>();
builder.Services.AddScoped<SecurityEventWriter>();
builder.Services.AddScoped<ClaimsPolicyService>();
builder.Services.AddScoped<ExternalIdentityService>();
// 接口注册：Admin 控制器以 ITokenRevoker 依赖（测试可替换；实现不变）。
builder.Services.AddScoped<ITokenRevoker, TokenRevocationService>();
// 登录时间侧信道拉平用的 dummy 哈希：必须单例（只算一次哈希），校验仍用 scoped hasher。
builder.Services.AddSingleton<DummyPasswordHash>();

// ---- 邮件通道（Resend，移植自 panda-asst-server）----
// 生产：缺 Email:ApiKey / Email:FromAddress 启动即失败（密钥经 compose 注入）；typed client
// 让 HttpClient 处理器轮换由工厂管理。开发：DevEmailSender 验证码落日志，零外部依赖。
// 注意：注册在 builder 阶段做环境判断用 builder.Environment（app 变量此时尚未创建）。
builder.Services.AddOptions<EmailOptions>()
    .Bind(builder.Configuration.GetSection(EmailOptions.SectionName))
    .Validate(options => !builder.Environment.IsProduction()
        || (!string.IsNullOrWhiteSpace(options.ApiKey) && !string.IsNullOrWhiteSpace(options.FromAddress)),
        "生产环境必须配置 Email:ApiKey 与 Email:FromAddress。")
    .ValidateOnStart();
if (builder.Environment.IsProduction())
{
    builder.Services.AddHttpClient<IEmailSender, ResendEmailSender>();
}
else
{
    builder.Services.AddSingleton<IEmailSender, DevEmailSender>();
}

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<OtpService>();
builder.Services.AddScoped<AccountVerificationService>();
// login_logs / admin_audit_logs 保留策略：后台按天删除超期审计记录（Auth:Audit:RetentionDays，默认 90 天）。
builder.Services.AddHostedService<LoginLogRetentionService>();
builder.Services.AddHealthChecks();

var app = builder.Build();

// Caddy 以 HTTP 反代到 127.0.0.1:9004 并终结 TLS，需还原真实 Scheme 与客户端 IP。
// 仅信任回环代理（Caddy 与容器同 host network，真实代理永远是回环地址）：伪造发生在 XFF 头链而非连接层，
// 端口绑定 127.0.0.1 不能消除伪造风险，全量网段信任属失败开放配置。
// ForwardLimit=1：只消费 Caddy 追加的最右一跳真实客户端 IP，攻击者伪造的最左值无法污染 IP 限流与审计。
//
// ⚠️ 本注册只覆盖「管线末端」的端点（控制器、静态文件等）。最小托管会把 UseAuthentication()
//    自动插到管线最前端，而 OpenIddict 的 discovery / connect 端点由认证中间件提供——它们在本行
//    之前就已处理请求，因此这里还原不了它们的 Scheme。这些端点依赖 compose 中的宿主级
//    ASPNETCORE_FORWARDEDHEADERS_ENABLED=true（更靠前，默认策略同为「仅信任回环 + ForwardLimit=1」）。
//    2026-09-16 实测：删掉该环境变量后，公网 discovery 的 authorization_endpoint 退化为 http://。
//    两者是分工而非重复，勿单独删除任何一个。
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
    ForwardLimit = 1,
    KnownProxies = { IPAddress.Loopback, IPAddress.IPv6Loopback },
});

app.UseMiddleware<SecurityHeadersMiddleware>();

// 品牌静态资源（wwwroot/brand/：登录页 favicon 与 mark），安全头之后挂载使 CSP 等头部同样覆盖静态响应。
app.UseStaticFiles();

// 公网形态（Caddy 同域分流，见元仓 WORKSPACE.md 路由表）只把 /connect/*、/account/*、/.well-known/*、
// /healthz 分给 IDP：登录视图引用的 /brand/* 在公网会落到门户 catch-all 而 404（2026-09-19 生产实测
// logo 404、破图）。故把 wwwroot/brand 以 /account/brand 前缀再挂一份——路径天然落在 IDP 的路由表内，
// 视图改引 /account/brand/*，不动 Caddy。本地直连 9004 时两种路径都可用。
app.UseStaticFiles(new StaticFileOptions
{
    RequestPath = "/account/brand",
    FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(
        Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "brand")),
});

if (app.Environment.IsDevelopment())
{
    // 开发环境：启动时幂等执行种子数据（生产通过 --migrate 显式执行）。
    using var seedScope = app.Services.CreateScope();
    await DbSeeder.SeedAsync(seedScope.ServiceProvider);
}

app.MapControllers();
app.MapHealthChecks("/healthz");

app.Run();

Uri IssuerUri()
{
    if (string.IsNullOrWhiteSpace(authOptions.Issuer))
    {
        throw new InvalidOperationException(
            "缺少 Auth:Issuer 配置。生产示例：Auth__Issuer=https://auth.pandalabs.cc");
    }

    return new Uri(authOptions.Issuer.EndsWith('/') ? authOptions.Issuer : authOptions.Issuer + "/", UriKind.Absolute);
}

// 供后续集成测试（WebApplicationFactory）使用。
public partial class Program;
