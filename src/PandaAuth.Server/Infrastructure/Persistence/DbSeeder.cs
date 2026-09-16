using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>幂等种子数据：管理员角色/账号、me-web 第一方客户端与可选 demo 客户端。</summary>
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
            await SeedMeWebApplicationAsync(applications, options.Seed.Me);
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

    /// <summary>me-web：账户中心第一方客户端；不存在则按配置创建，已存在则按配置订正回调白名单（upsert）。</summary>
    private static async Task SeedMeWebApplicationAsync(IOpenIddictApplicationManager applications, MeSeedOptions me)
    {
        var existing = await applications.FindByClientIdAsync("me-web");
        if (existing is null)
        {
            // 回调白名单经 Auth:Seed:Me:RedirectUris / Auth:Seed:Me:PostLogoutRedirectUris 配置注入，缺失即失败（第一方必备客户端）。
            if (me.RedirectUris.Length == 0)
            {
                throw new InvalidOperationException("缺少 Auth:Seed:Me:RedirectUris 配置（me-web 为第一方必备客户端）。");
            }

            if (me.PostLogoutRedirectUris.Length == 0)
            {
                throw new InvalidOperationException(
                    "缺少 Auth:Seed:Me:PostLogoutRedirectUris 配置（me-web 为第一方必备客户端）。");
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "me-web",
                ClientType = ClientTypes.Confidential,
                ClientSecret = string.IsNullOrWhiteSpace(me.ClientSecret)
                    ? throw new InvalidOperationException("缺少 Auth:Seed:Me:ClientSecret 配置。")
                    : me.ClientSecret,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "PandaAuth 账户中心",
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

            foreach (var uri in me.RedirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }

            foreach (var uri in me.PostLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }

            await applications.CreateAsync(descriptor);
            return;
        }

        // 存量订正：配置数组非空时用配置值整体替换对应白名单（如 .cn → .cc 域名切换），
        // 两者皆空则不动；不触碰密钥等其他字段。全部经 ApplicationManager API 完成，不直接写 EF。
        if (me.RedirectUris.Length == 0 && me.PostLogoutRedirectUris.Length == 0)
        {
            return;
        }

        var updated = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(updated, existing);

        if (me.RedirectUris.Length > 0)
        {
            updated.RedirectUris.Clear();
            foreach (var uri in me.RedirectUris)
            {
                updated.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }
        }

        if (me.PostLogoutRedirectUris.Length > 0)
        {
            updated.PostLogoutRedirectUris.Clear();
            foreach (var uri in me.PostLogoutRedirectUris)
            {
                updated.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }
        }

        await applications.PopulateAsync(existing, updated);
        await applications.UpdateAsync(existing);
    }
}
