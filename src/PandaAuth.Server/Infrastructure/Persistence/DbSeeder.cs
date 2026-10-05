using PandaAuth.Server.Infrastructure.Security;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using PandaAuth.Server.Configuration;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Infrastructure.Persistence;

/// <summary>幂等种子数据：管理员角色/账号、me-web/admin-web/oasis-web 第一方客户端、可选 fleet/mgmt/demo 客户端。</summary>
public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<AuthOptions>>().Value;
        if (!options.Seed.Enabled)
        {
            return;
        }

        var roleManager = services.GetRequiredService<RoleService>();
        var userManager = services.GetRequiredService<UserService>();
        var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = services.GetRequiredService<IOpenIddictScopeManager>();

        if (!await roleManager.RoleExistsAsync(PandaUser.AdminRole))
        {
            var roleResult = await roleManager.CreateAsync(new PandaRole { Name = PandaUser.AdminRole });
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
                admin = new PandaUser
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

                await userManager.AddToRoleAsync(admin, PandaUser.AdminRole);
            }
        }

        if (options.Seed.Demo.Enabled)
        {
            await SeedDemoApplicationsAsync(applications, options.Seed.Demo);
        }

        if (options.Seed.Me.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(applications, "me-web", "PandaAuth 账户中心", "Auth:Seed:Me", options.Seed.Me, options.TenantRouting, "me");
        }

        if (options.Seed.AdminWeb.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(
                applications, "admin-web", "PandaAuth 管理后台", "Auth:Seed:AdminWeb", options.Seed.AdminWeb, options.TenantRouting, "admin");
        }

        // Oasis 不挂在 PandaAuth 租户路由下（独立产品域），不参与租户回调展开；
        // 权限集用裁剪版（无 roles scope、无 Introspection 端点）。
        if (options.Seed.OasisWeb.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(
                applications, "oasis-web", "Oasis 工作台", "Auth:Seed:OasisWeb", options.Seed.OasisWeb,
                permissions: OasisWebPermissions());
        }

        // Fleet 管理台只部署在 Fleet 控制面（专用 PandaAuth 实例）；回调不参与租户路由展开。
        if (options.Seed.FleetAdminWeb.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(
                applications, "fleet-admin-web", "Panda Fleet 管理台", "Auth:Seed:FleetAdminWeb", options.Seed.FleetAdminWeb,
                permissions: FleetAdminWebPermissions());
        }

        // Panda Assistant 客户端族（PANDA-INFRA-R1，panda-asst ADR 0095）：默认关闭，
        // 仅 panda-asst 租户实例（t####-auth）显式开启；asst 回调展开按 PandaAssistant 绑定。
        if (options.Seed.AsstWeb.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(
                applications, "asst-web", "熊猫助理工作台", "Auth:Seed:AsstWeb", options.Seed.AsstWeb,
                options.TenantRouting, "app", AsstClientPermissions(), TenantProduct.PandaAssistant,
                postLogoutSuffix: "callback/logout/pandaauth");
        }

        if (options.Seed.AsstAdmin.Enabled)
        {
            await SeedFirstPartyWebApplicationAsync(
                applications, "asst-admin", "熊猫助理管理后台", "Auth:Seed:AsstAdmin", options.Seed.AsstAdmin,
                options.TenantRouting, "admin", AsstClientPermissions(), TenantProduct.PandaAssistant,
                postLogoutSuffix: "callback/logout/pandaauth");
        }

        if (options.Seed.AsstMobile.Enabled)
        {
            await SeedAsstMobileApplicationAsync(applications, options.Seed.AsstMobile);
        }

        if (options.Seed.AsstServer.Enabled)
        {
            await SeedAsstServerApplicationAsync(applications, options.Seed.AsstServer);
        }

        if (options.Seed.Fleet.Enabled)
        {
            await SeedFleetScopesAsync(scopes);
            await SeedFleetApplicationAsync(applications, options.Seed.Fleet);
        }

        if (options.Seed.Mgmt.Enabled)
        {
            await SeedMgmtScopesAsync(scopes);
            await SeedMgmtApplicationAsync(applications, options.Seed.Mgmt);
        }
    }

    private static async Task SeedFleetScopesAsync(IOpenIddictScopeManager scopes)
    {
        foreach (var name in new[] { "fleet.read", "fleet.allocate", "fleet.apply", "fleet.server.manage" })
        {
            if (await scopes.FindByNameAsync(name) is not null) continue;

            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = $"PandaLabs Fleet {name[6..]}",
                Resources = { "fleet-api" },
            });
        }
    }

    private static async Task SeedFleetApplicationAsync(IOpenIddictApplicationManager applications, FleetSeedOptions fleet)
    {
        if (string.IsNullOrWhiteSpace(fleet.ClientSecret))
        {
            throw new InvalidOperationException("缺少 Auth:Seed:Fleet:ClientSecret 配置（fleet-api 客户端密钥）。");
        }

        var existing = await applications.FindByClientIdAsync("fleet-api");
        if (existing is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "fleet-api",
                ClientType = ClientTypes.Confidential,
                ClientSecret = fleet.ClientSecret,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "PandaLabs Fleet 控制面 API",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Introspection,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "fleet.read",
                    Permissions.Prefixes.Scope + "fleet.allocate",
                    Permissions.Prefixes.Scope + "fleet.apply",
                    Permissions.Prefixes.Scope + "fleet.server.manage",
                },
            });
            return;
        }

        if (!await applications.ValidateClientSecretAsync(existing, fleet.ClientSecret))
        {
            await applications.UpdateAsync(existing, fleet.ClientSecret);
        }
    }

    /// <summary>
    /// Management API（M0）：
    /// mgmt.* scope 绑定 panda-mgmt-api 资源；专用机密客户端 mgmt-api 只含管理 scope。
    /// 交互式应用客户端一律不追加管理 scope——Auth0 组织级 M2M 无法访问管理 API 教训的直接落实。
    /// </summary>
    private static async Task SeedMgmtScopesAsync(IOpenIddictScopeManager scopes)
    {
        foreach (var name in new[]
                 {
                     Features.Management.MgmtApiAuthorization.ClientsReadScope,
                     Features.Management.MgmtApiAuthorization.ClientsWriteScope,
                     Features.Management.MgmtApiAuthorization.UsersReadScope,
                 })
        {
            if (await scopes.FindByNameAsync(name) is not null) continue;

            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = $"PandaAuth Management API: {name}",
                Resources = { Features.Management.MgmtApiAuthorization.Audience },
            });
        }
    }

    private static async Task SeedMgmtApplicationAsync(IOpenIddictApplicationManager applications, MgmtSeedOptions mgmt)
    {
        if (string.IsNullOrWhiteSpace(mgmt.ClientSecret))
        {
            throw new InvalidOperationException(
                "Auth:Seed:Mgmt:Enabled=true 但缺少 Auth:Seed:Mgmt:ClientSecret 配置（mgmt-api 机密客户端密钥）。");
        }

        var existing = await applications.FindByClientIdAsync("mgmt-api");
        if (existing is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mgmt-api",
                ClientType = ClientTypes.Confidential,
                ClientSecret = mgmt.ClientSecret,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "PandaAuth Management API",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Introspection,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + Features.Management.MgmtApiAuthorization.ClientsReadScope,
                    Permissions.Prefixes.Scope + Features.Management.MgmtApiAuthorization.ClientsWriteScope,
                    Permissions.Prefixes.Scope + Features.Management.MgmtApiAuthorization.UsersReadScope,
                },
            });
            return;
        }

        if (!await applications.ValidateClientSecretAsync(existing, mgmt.ClientSecret))
        {
            await applications.UpdateAsync(existing, mgmt.ClientSecret);
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
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "api",
                },
            });
        }
    }

    /// <summary>
    /// 第一方机密 Web 客户端（me-web / admin-web / oasis-web）的 upsert 播种：不存在则按配置创建，
    /// 已存在则按配置订正回调白名单与客户端密钥。共用本方法，行为一致；差异（权限集、租户回调展开）
    /// 经 permissions / tenantRouting 参数表达。
    /// </summary>
    private static async Task SeedFirstPartyWebApplicationAsync(
        IOpenIddictApplicationManager applications,
        string clientId,
        string displayName,
        string configPrefix,
        FirstPartyWebSeedOptions seed,
        TenantRoutingOptions? tenantRouting = null,
        string? callbackArea = null,
        string[]? permissions = null,
        TenantProduct tenantHostProduct = TenantProduct.PandaAuth,
        string postLogoutSuffix = "")
    {
        permissions ??= FirstPartyWebPermissions();
        var redirectUris = ExpandTenantRedirectUris(seed.RedirectUris, tenantRouting, callbackArea, "callback/login/pandaauth", tenantHostProduct);
        // post-logout 回调必须是专用路径：应用根（如 /app/）会被 OpenIddict 客户端拦截做登出回调提取，
        // 无 state 的普通导航被当作回调以 400 拒绝（me-web 2026-10-01 实测教训）。asst 客户端用 callback/logout/pandaauth。
        var postLogoutRedirectUris = ExpandTenantRedirectUris(seed.PostLogoutRedirectUris, tenantRouting, callbackArea, postLogoutSuffix, tenantHostProduct);
        var existing = await applications.FindByClientIdAsync(clientId);
        if (existing is null)
        {
            // 回调白名单经 {configPrefix}:RedirectUris / PostLogoutRedirectUris 配置注入，缺失即失败（第一方必备客户端）。
            if (redirectUris.Length == 0)
            {
                throw new InvalidOperationException($"缺少 {configPrefix}:RedirectUris 配置（{clientId} 为第一方必备客户端）。");
            }

            if (postLogoutRedirectUris.Length == 0)
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
            };

            foreach (var permission in permissions)
            {
                descriptor.Permissions.Add(permission);
            }

            foreach (var uri in redirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }

            foreach (var uri in postLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }

            await applications.CreateAsync(descriptor);
            return;
        }

        // 存量订正：白名单替换与密钥对账各自独立判断，两者都不需要做时才提前返回——
        // 旧实现见任一白名单数组为空就 return，会连带跳过密钥对账。
        // 全部经 ApplicationManager API 完成，不直接写 EF。
        var replaceRedirectUris = redirectUris.Length > 0;
        var replacePostLogoutRedirectUris = postLogoutRedirectUris.Length > 0;

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
                foreach (var uri in redirectUris)
                {
                    updated.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
                }
            }

            if (replacePostLogoutRedirectUris)
            {
                updated.PostLogoutRedirectUris.Clear();
                foreach (var uri in postLogoutRedirectUris)
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

    /// <summary>
    /// me-web / admin-web 的默认权限集：授权码 + PKCE + 刷新令牌，含 roles scope、
    /// Revocation 端点（登出时吊销 IdP 令牌）。PandaAuth 自带面板的工作台门禁依赖 roles。
    /// </summary>
    private static string[] FirstPartyWebPermissions() =>
    [
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
    ];

    /// <summary>
    /// oasis-web 权限集 = 默认第一方 Web 权限集裁掉两项：
    /// - roles scope 不授——Oasis 明确不请求 roles，授权完全在 Oasis 本地（镜像于 Oasis 侧
    ///   registration 的 scopes 注释，避免将来误请求时悄悄把工作台角色带进 token）；
    /// - Introspection 端点不授——Oasis 不消费内省（token 仅存服务端 cookie）。
    /// Revocation 端点保留：Oasis 登出走 RP-initiated signout + revoke（me-web 模式），
    /// 缺该权限会让登出时的令牌吊销在 IdP 侧被拒，只能靠 best-effort 日志发现。
    /// </summary>
    private static string[] OasisWebPermissions() =>
    [
        Permissions.Endpoints.Authorization,
        Permissions.Endpoints.Token,
        Permissions.Endpoints.EndSession,
        Permissions.Endpoints.Revocation,
        Permissions.GrantTypes.AuthorizationCode,
        Permissions.GrantTypes.RefreshToken,
        Permissions.ResponseTypes.Code,
        Permissions.Scopes.Email,
        Permissions.Scopes.Profile,
        Permissions.Prefixes.Scope + Scopes.OfflineAccess,
        Requirements.Features.ProofKeyForCodeExchange,
    ];

    /// <summary>
    /// asst-web / asst-admin / asst-mobile 权限集 = oasis-web 同款裁剪：
    /// - roles scope 不授——Panda Assistant 授权完全在 asst 本地（Admin:Emails / AccessGrant），不得制造第二套授权来源；
    /// - Introspection 端点不授——内省只属于 asst-server（资源方）。
    /// Revocation 端点保留：BFF 登出走 RP-initiated signout + revoke。
    /// </summary>
    private static string[] AsstClientPermissions() =>
    [
        Permissions.Endpoints.Authorization,
        Permissions.Endpoints.Token,
        Permissions.Endpoints.EndSession,
        Permissions.Endpoints.Revocation,
        Permissions.GrantTypes.AuthorizationCode,
        Permissions.GrantTypes.RefreshToken,
        Permissions.ResponseTypes.Code,
        Permissions.Scopes.Email,
        Permissions.Scopes.Profile,
        Permissions.Prefixes.Scope + Scopes.OfflineAccess,
        Requirements.Features.ProofKeyForCodeExchange,
    ];

    /// <summary>
    /// fleet-admin-web 权限集 = 第一方 Web 基础集（含 roles scope 与 Introspection/Revocation 端点）
    /// + fleet.* 委托作用域四项：管理台以 BFF 形态代表操作者调用 Fleet Server，
    /// scope 的 Resources 指向 fleet-api（SeedFleetScopesAsync），token 受众由此落到 fleet-api。
    /// roles 保留：Fleet 操作审计的 actor 断言需要角色声明。
    /// </summary>
    private static string[] FleetAdminWebPermissions() =>
    [
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
        Permissions.Prefixes.Scope + "fleet.read",
        Permissions.Prefixes.Scope + "fleet.allocate",
        Permissions.Prefixes.Scope + "fleet.apply",
        Permissions.Prefixes.Scope + "fleet.server.manage",
        Requirements.Features.ProofKeyForCodeExchange,
    ];

    private static string[] ExpandTenantRedirectUris(
        string[] configuredUris,
        TenantRoutingOptions? tenantRouting,
        string? callbackArea,
        string suffix,
        TenantProduct hostProduct = TenantProduct.PandaAuth)
    {
        if (tenantRouting is null || callbackArea is null)
            return configuredUris;

        var tenantUris = tenantRouting.Bindings
            .Where(binding => binding.Product == hostProduct && binding.State == TenantRouteState.Ready)
            .Select(binding =>
            {
                var host = TenantCanonicalHost.For(TenantId.Parse(binding.TenantId), hostProduct, binding.Zone);
                return suffix.Length == 0
                    ? $"https://{host}/{callbackArea}/"
                    : $"https://{host}/{callbackArea}/{suffix}";
            });

        return configuredUris.Concat(tenantUris).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>
    /// asst-mobile（公共客户端 / PKCE）的 upsert 播种：无密钥，仅回调白名单订正；
    /// 回调为 App Links（https://t####-asst.sNNN.../app/callback/mobile），全部经配置注入。
    /// </summary>
    private static async Task SeedAsstMobileApplicationAsync(IOpenIddictApplicationManager applications, AsstMobileSeedOptions seed)
    {
        var existing = await applications.FindByClientIdAsync("asst-mobile");
        if (existing is null)
        {
            if (seed.RedirectUris.Length == 0)
            {
                throw new InvalidOperationException("缺少 Auth:Seed:AsstMobile:RedirectUris 配置（asst-mobile 为 App Links 公共客户端）。");
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "asst-mobile",
                ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "熊猫助理 App（公共客户端 / PKCE）",
            };
            foreach (var permission in AsstClientPermissions())
            {
                descriptor.Permissions.Add(permission);
            }
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

        var replaceRedirectUris = seed.RedirectUris.Length > 0;
        var replacePostLogout = seed.PostLogoutRedirectUris.Length > 0;
        if (!replaceRedirectUris && !replacePostLogout)
            return;

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
        if (replacePostLogout)
        {
            updated.PostLogoutRedirectUris.Clear();
            foreach (var uri in seed.PostLogoutRedirectUris)
            {
                updated.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));
            }
        }
        await applications.PopulateAsync(existing, updated);
        await applications.UpdateAsync(existing);
    }

    /// <summary>
    /// asst-server（资源方机密客户端）：仅内省端点权限——换发端点（panda-asst /auth/oidc/exchange）
    /// 以本客户端凭据对用户令牌做一次性 introspection；无回调、无授权码面。
    /// </summary>
    private static async Task SeedAsstServerApplicationAsync(IOpenIddictApplicationManager applications, AsstServerSeedOptions seed)
    {
        if (string.IsNullOrWhiteSpace(seed.ClientSecret))
        {
            throw new InvalidOperationException("缺少 Auth:Seed:AsstServer:ClientSecret 配置（asst-server 内省客户端密钥）。");
        }

        var existing = await applications.FindByClientIdAsync("asst-server");
        if (existing is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "asst-server",
                ClientType = ClientTypes.Confidential,
                ClientSecret = seed.ClientSecret,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "熊猫助理 API（内省客户端）",
                Permissions =
                {
                    Permissions.Endpoints.Introspection,
                },
            });
            return;
        }

        if (!await applications.ValidateClientSecretAsync(existing, seed.ClientSecret))
        {
            await applications.UpdateAsync(existing, seed.ClientSecret);
        }
    }
}
