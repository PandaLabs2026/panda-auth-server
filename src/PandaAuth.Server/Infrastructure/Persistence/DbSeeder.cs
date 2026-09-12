using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>幂等种子数据：管理员角色/账号与内置演示客户端。</summary>
public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<AuthOptions>>().Value;
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

        if (options.Seed.AdminPassword.Length > 0)
        {
            var admin = await userManager.FindByNameAsync(options.Seed.AdminEmail);
            if (admin is null)
            {
                admin = new PandaAuthUser
                {
                    UserName = options.Seed.AdminEmail,
                    Email = options.Seed.AdminEmail,
                    EmailConfirmed = true,
                    Nickname = "PandaAdmin",
                    RegisterChannel = RegisterChannel.Password,
                };
                var userResult = await userManager.CreateAsync(admin, options.Seed.AdminPassword);
                if (!userResult.Succeeded)
                {
                    throw new InvalidOperationException(
                        $"创建管理员账号失败：{string.Join("; ", userResult.Errors.Select(e => e.Description))}");
                }

                await userManager.AddToRoleAsync(admin, PandaAuthUser.AdminRole);
            }
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
                ClientSecret = "demo-web-secret-change-me",
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
                ClientSecret = "demo-service-secret-change-me",
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
}
