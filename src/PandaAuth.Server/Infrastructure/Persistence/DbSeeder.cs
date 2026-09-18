using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>幂等种子数据：管理员角色/账号、me-web 与 admin-web 第一方客户端、可选 demo 客户端。</summary>
public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<AuthOptions>>().Value;
        if (!options.Seed.Enabled)
        {
            return;
        }

        var roleManager = services.GetRequiredService<RoleManager<PandaAuthRole>>();
        var userManager = services.GetRequiredService<UserManager<PandaAuthUser>>();
        var applications = services.GetRequiredService<IOpenIddictApplicationManager>();

        if (!await roleManager.RoleExistsAsync(PandaAuthUser.AdminRole))
        {
            var roleResult = await roleManager.CreateAsync(new PandaAuthRole { Name = PandaAuthUser.AdminRole });
            if (!roleResult.Succeeded)
            {
                throw new InvalidOperationException(
                    $"创建管理员角色失败：{string.Join("; ", roleResult.Errors.Select(e => e.Description))}");
            }
        }

        if (options.Seed.Admin.Password.Length > 0)
        {
            var admin = await userManager.FindByNameAsync(options.Seed.Admin.Email);
            if (admin is null)
            {
                admin = new PandaAuthUser
                {
                    UserName = options.Seed.Admin.Email,
                    Email = options.Seed.Admin.Email,
                    EmailConfirmed = true,
                    Nickname = "PandaAdmin",
                    RegisterChannel = RegisterChannel.Password,
                };
                var userResult = await userManager.CreateAsync(admin, options.Seed.Admin.Password);
                if (!userResult.Succeeded)
                {
                    throw new InvalidOperationException(
                        $"创建管理员账号失败：{string.Join("; ", userResult.Errors.Select(e => e.Description))}");
                }

                await userManager.AddToRoleAsync(admin, PandaAuthUser.AdminRole);
            }
        }

        if (options.Seed.Demo.Enabled)
        {
            await SeedDemoApplicationsAsync(applications, options.Seed.Demo);
        }

        if (options.Seed.Me.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(applications, "me-web", "PandaAuth 账户中心", "Auth:Seed:Me", options.Seed.Me);
        }

        if (options.Seed.AdminWeb.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(
                applications, "admin-web", "PandaAuth 管理后台", "Auth:Seed:AdminWeb", options.Seed.AdminWeb);
        }
    }

    /// <summary>demo 三客户端：默认关闭播种；开启后密钥必须经配置注入，源码不内置任何密钥常量。</summary>
    private static async Task SeedDemoApplicationsAsync(IOpenIddictApplicationManager applications, DemoSeedOptions demo)
    {
        if (demo.WebSecret.Length == 0)
        {
            throw new InvalidOperationException(
                "Auth:Seed:Demo:Enabled=true 但缺少 Auth:Seed:Demo:WebSecret 配置（demo-web 机密客户端密钥）。");
        }

        if (demo.ServiceSecret.Length == 0)
        {
            throw new InvalidOperationException(
                "Auth:Seed:Demo:Enabled=true 但缺少 Auth:Seed:Demo:ServiceSecret 配置（demo-service 机密客户端密钥）。");
        }

        // demo-public：公共客户端（模拟移动端/桌面端），授权码 + 强制 PKCE + 刷新令牌。
        if (await applications.FindByClientIdAsync("demo-public") is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "demo-public",
                ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "PandaAuth Demo（公共客户端 / PKCE）",
                RedirectUris = { new Uri("http://localhost:5201/callback/login/pandaauth") },
                PostLogoutRedirectUris = { new Uri("http://localhost:5201/") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Requirements.Features.ProofKeyForCodeExchange,
                },
            });
        }

        // demo-web：机密客户端（模拟传统 Web 应用后端托管凭证），授权码 + PKCE + 刷新令牌。
        if (await applications.FindByClientIdAsync("demo-web") is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "demo-web",
                ClientType = ClientTypes.Confidential,
                ClientSecret = demo.WebSecret,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "PandaAuth Demo（机密客户端）",
                RedirectUris = { new Uri("http://localhost:5201/callback/login/pandaauth") },
                PostLogoutRedirectUris = { new Uri("http://localhost:5201/") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Requirements.Features.ProofKeyForCodeExchange,
                },
            });
        }

        // demo-service：机密客户端，客户端凭证模式（服务间调用）。
        if (await applications.FindByClientIdAsync("demo-service") is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "demo-service",
                ClientType = ClientTypes.Confidential,
                ClientSecret = demo.ServiceSecret,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "PandaAuth Demo（服务间调用）",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Introspection,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "api",
                },
            });
        }
    }

    /// <summary>
    /// 第一方机密 Web 客户端（me-web / admin-web）的 upsert 播种：不存在则按配置创建，
    /// 已存在则按配置订正回调白名单与客户端密钥。两者共用本方法，行为一致。
    /// </summary>
    private static async Task SeedFirstPartyWebApplicationAsync(
        IOpenIddictApplicationManager applications,
        string clientId,
        string displayName,
        string configPrefix,
        FirstPartyWebSeedOptions seed)
    {
        var existing = await applications.FindByClientIdAsync(clientId);
        if (existing is null)
        {
            // 回调白名单经 {configPrefix}:RedirectUris / PostLogoutRedirectUris 配置注入，缺失即失败（第一方必备客户端）。
            if (seed.RedirectUris.Length == 0)
            {
                throw new InvalidOperationException($"缺少 {configPrefix}:RedirectUris 配置（{clientId} 为第一方必备客户端）。");
            }

            if (seed.PostLogoutRedirectUris.Length == 0)
            {
                throw new InvalidOperationException(
                    $"缺少 {configPrefix}:PostLogoutRedirectUris 配置（{clientId} 为第一方必备客户端）。");
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientType = ClientTypes.Confidential,
                ClientSecret = string.IsNullOrWhiteSpace(seed.ClientSecret)
                    ? throw new InvalidOperationException($"缺少 {configPrefix}:ClientSecret 配置。")
                    : seed.ClientSecret,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = displayName,
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Requirements.Features.ProofKeyForCodeExchange,
                },
            };

            foreach (var uri in seed.RedirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }

            foreach (var uri in seed.PostLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }

            await applications.CreateAsync(descriptor);
            return;
        }

        // 存量订正：白名单替换与密钥对账各自独立判断，两者都不需要做时才提前返回——
        // 旧实现见任一白名单数组为空就 return，会连带跳过密钥对账。
        // 全部经 ApplicationManager API 完成，不直接写 EF。
        var replaceRedirectUris = seed.RedirectUris.Length > 0;
        var replacePostLogoutRedirectUris = seed.PostLogoutRedirectUris.Length > 0;

        // 密钥对账：密钥唯一事实源是服务器 env 文件（{configPrefix}:ClientSecret）。
        // 幂等依据：ValidateClientSecretAsync 命中即说明库内哈希已对应配置密钥，此时不改写；
        // 反证——UpdateAsync(application, secret) 每次都重新加盐哈希，无守卫地调用会让密钥哈希列
        // 每次 migrate 都变化（实证见 tests/PandaAuth.Tests 的密钥对账用例）。
        // 配置密钥缺失（空/空白）时跳过对账且不抛异常：创建路径抛是因为第一方客户端必须有密钥，
        // 而更新路径上贸然抛异常会让「已存在的部署 + 临时未配密钥」的 migrate 直接失败，风险更大。
        var reconcileSecret = !string.IsNullOrWhiteSpace(seed.ClientSecret) &&
            !await applications.ValidateClientSecretAsync(existing, seed.ClientSecret);

        if (!replaceRedirectUris && !replacePostLogoutRedirectUris && !reconcileSecret)
        {
            return;
        }

        if (replaceRedirectUris || replacePostLogoutRedirectUris)
        {
            var updated = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(updated, existing);

            if (replaceRedirectUris)
            {
                updated.RedirectUris.Clear();
                foreach (var uri in seed.RedirectUris)
                {
                    updated.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
                }
            }

            if (replacePostLogoutRedirectUris)
            {
                updated.PostLogoutRedirectUris.Clear();
                foreach (var uri in seed.PostLogoutRedirectUris)
                {
                    updated.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
                }
            }

            await applications.PopulateAsync(existing, updated);
        }

        // 密钥改写必须走 UpdateAsync(application, secret)：它才是会重新哈希的那条路径。
        // 不能用 descriptor.ClientSecret + PopulateAsync 写回——实测那是逐字拷贝、不哈希，
        // 结果是明文入库且新旧密钥双双校验失败（等于把客户端登不进来）。
        // 顺序上密钥更新必须排在白名单写回之后：PopulateAsync 写回会把读出时拿到的旧哈希原样写回，
        // 若先改密钥再写回，新哈希会被旧哈希覆盖掉（实测如此）。
        if (reconcileSecret)
        {
            await applications.UpdateAsync(existing, seed.ClientSecret);
        }
        else if (replaceRedirectUris || replacePostLogoutRedirectUris)
        {
            await applications.UpdateAsync(existing);
        }
    }
}
