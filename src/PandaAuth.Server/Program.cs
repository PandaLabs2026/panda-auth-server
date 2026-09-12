using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("缺少连接字符串 ConnectionStrings:Default。");

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.SectionName));
var authOptions = builder.Configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>() ?? new AuthOptions();

var isMigrateCommand = args.Contains("--migrate", StringComparer.Ordinal);

builder.Services.AddDbContext<PandaAuthDbContext>(options =>
{
    options.UseNpgsql(connectionString);
    options.UseOpenIddict();
});

builder.Services.AddIdentityCore<PandaAuthUser>(options =>
{
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Password.RequiredLength = 10;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
})
.AddRoles<PandaAuthRole>()
.AddEntityFrameworkStores<PandaAuthDbContext>()
.AddSignInManager()
.AddDefaultTokenProviders();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
        options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
    })
    .AddIdentityCookies(options =>
    {
        options.ApplicationCookie?.Configure(cookie =>
        {
            cookie.LoginPath = "/account/login";
            cookie.Cookie.Name = "PandaAuth.Login";
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SameSite = SameSiteMode.Lax;
            cookie.Cookie.SecurePolicy = authOptions.HttpsRequired
                ? CookieSecurePolicy.Always
                : CookieSecurePolicy.SameAsRequest;
        });
    });

// Argon2id 替换 Identity 默认哈希器（文档门禁：无明文、无 MD5、无 SHA256 裸存）。
builder.Services.AddScoped<IPasswordHasher<PandaAuthUser>, Argon2idPasswordHasher>();

if (authOptions.DataProtectionKeyPath.Length > 0)
{
    builder.Services
        .AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(authOptions.DataProtectionKeyPath))
        .SetApplicationName("PandaAuth");
}

// 一次性迁移模式：docker compose run --rm auth-server --migrate（生产发布流程）。
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

builder.Services
    .AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>())
    .AddServer(options =>
    {
        options
            .AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowClientCredentialsFlow()
            .AllowRefreshTokenFlow();

        options.SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetUserInfoEndpointUris("/connect/userinfo")
            .SetEndSessionEndpointUris("/connect/logout")
            .SetIntrospectionEndpointUris("/connect/introspect")
            .SetRevocationEndpointUris("/connect/revoke");

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

        // Issuer 全部来自配置（生产 https://auth.pandalabs.cn，海外实例改环境变量即可，零代码切换）。
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
    });

builder.Services.AddSingleton<LoginRateLimiter>();
builder.Services.AddScoped<LoginAuditWriter>();
builder.Services.AddScoped<TokenRevocationService>();
builder.Services.AddHealthChecks();

var app = builder.Build();

// Caddy 以 HTTP 反代到 127.0.0.1:9004 并终结 TLS，需还原真实 Scheme 与客户端 IP。
// 端口仅绑定 127.0.0.1，信任所有来源网络不会引入公网伪造风险。
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
    KnownIPNetworks =
    {
        new System.Net.IPNetwork(IPAddress.Any, 0),
        new System.Net.IPNetwork(IPAddress.IPv6Any, 0),
    },
    KnownProxies = { IPAddress.Loopback, IPAddress.IPv6Loopback },
});

app.UseMiddleware<SecurityHeadersMiddleware>();

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
            "缺少 Auth:Issuer 配置。生产示例：Auth__Issuer=https://auth.pandalabs.cn");
    }

    return new Uri(authOptions.Issuer.EndsWith('/') ? authOptions.Issuer : authOptions.Issuer + "/", UriKind.Absolute);
}

// 供后续集成测试（WebApplicationFactory）使用。
public partial class Program;
