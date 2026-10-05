using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using PandaAuth.Server.Infrastructure.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Authorization;

[Route("~/connect")]
public sealed class AuthorizationController(
    UserService userManager,
    LoginSessionService signInManager,
    ClaimsPolicyService claimsPolicy,
    IOpenIddictScopeManager scopeManager,
    ITenantContextAccessor tenantContextAccessor,
    TenantRedirectPolicy tenantRedirectPolicy,
    TimeProvider clock) : Controller
{
    [HttpGet("authorize")]
    // 不挂 [Authorize]：它会在动作前抢先把未认证请求 302 到登录页，使 prompt=none 无法按 OIDC
    // 以 error=login_required 回 redirect_uri。认证改为动作内手动 AuthenticateAsync，
    // 挑战/报错语义（prompt/max_age/租户/账号状态）全部在协议层统一裁决。
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("无法解析 OIDC 授权请求。");

        if (tenantContextAccessor.Current is { } tenant
            && (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out var redirectUri)
                || !tenantRedirectPolicy.IsAllowed(tenant, redirectUri)))
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "redirect_uri 必须属于当前租户。",
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var authResult = await HttpContext.AuthenticateAsync(LoginSessionService.Scheme);
        if (authResult is not { Succeeded: true })
        {
            // prompt=none：客户端声明不得出现交互界面——未认证时按 OIDC 必须把
            // error=login_required 302 回 redirect_uri，而不是把用户送去登录页。
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "用户未认证，而请求要求不进行交互（prompt=none）。",
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return Challenge(
                new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString },
                LoginSessionService.Scheme);
        }

        // Legacy or malformed cookies must establish a new real login, never synthesize "now".
        if (!FleetHumanPrincipalClaims.TryReadAuthenticationTime(authResult.Principal, LoginSessionService.AuthenticatedAtClaim, out var authenticatedAt))
        {
            await signInManager.SignOutAsync(HttpContext);
            return Challenge(
                new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString },
                LoginSessionService.Scheme);
        }

        var user = await userManager.GetUserAsync(authResult.Principal!);
        if (user is null || user.Status != UserStatus.Active)
        {
            await signInManager.SignOutAsync(HttpContext);
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "账号不存在或已被冻结。",
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // prompt=login / max_age 超龄：客户端要求一次比当前会话更新的认证。先注销当前会话再挑战，
        // 强制回登录页——静默放行会让过期会话继续发码，auth_time 语义失真（Fleet auth_time 契约）。
        if (request.HasPromptValue(PromptValues.Login) ||
            ExceedsMaxAge(request.MaxAge, authenticatedAt, clock.GetUtcNow().ToUnixTimeSeconds()))
        {
            await signInManager.SignOutAsync(HttpContext);
            return Challenge(
                new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString },
                LoginSessionService.Scheme);
        }

        var principal = await CreatePrincipalAsync(user, request.GetScopes(), authResult.Principal);

        // P0：内部生态客户端 ConsentType=Implicit，自动同意；交互式授权确认页属 Phase 1。
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("无法解析 OIDC Token 请求。");

        if (request.IsClientCredentialsGrantType())
        {
            // 服务间调用：仅授予客户端身份，不涉及终端用户。
            var clientIdentity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
            clientIdentity.AddClaim(new Claim(Claims.Subject, request.ClientId!));
            clientIdentity.AddClaim(new Claim(Claims.Name, request.ClientId!));
            clientIdentity.AddClaim(new Claim(Claims.ClientId, request.ClientId!));
            // 控制面契约：client_credentials 永远是机器主体，绝不冒充人类审批身份。
            clientIdentity.AddClaim(new Claim(PandaAuthClaims.SubjectType, PandaAuthClaims.SubjectTypes.Machine));
            clientIdentity.SetScopes(request.GetScopes());
            // audience 来自 scope 实体的资源绑定（fleet.* → fleet-api、mgmt.* → panda-mgmt-api），
            // 不在控制器里硬编码资源名——新 scope 绑定资源后令牌自动携带对应 audience。
            clientIdentity.SetResources(await scopeManager.ListResourcesAsync(request.GetScopes(), HttpContext.RequestAborted).ToListAsync(HttpContext.RequestAborted));

            var clientPrincipal = new ClaimsPrincipal(clientIdentity);
            clientPrincipal.SetDestinations(static _ => [Destinations.AccessToken]);

            return SignIn(clientPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // 授权码 / 刷新令牌：从票据中恢复用户并校验账号状态（冻结/注销立即失效）。
        var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!authResult.Succeeded ||
            !FleetHumanPrincipalClaims.TryReadAuthenticationTime(authResult.Principal, Claims.AuthenticationTime, out _))
        {
            return InvalidGrant("授权票据缺少有效的原始认证时间。");
        }
        var userId = authResult.Principal?.GetClaim(Claims.Subject);
        if (string.IsNullOrEmpty(userId))
        {
            return InvalidGrant("授权票据无效或已过期。");
        }

        var user = await userManager.FindByIdAsync(userId);
        if (user is null || user.Status != UserStatus.Active)
        {
            return InvalidGrant("账号不存在或已被冻结。");
        }

        var principal = await CreatePrincipalAsync(user, authResult.Principal!.GetScopes(), authResult.Principal,
            Claims.AuthenticationTime);
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("userinfo")]
    [HttpPost("userinfo")]
    [Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true } || result.Principal is null)
        {
            return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var principal = result.Principal;
        var response = new Dictionary<string, object?>
        {
            [Claims.Subject] = principal.GetClaim(Claims.Subject) ?? string.Empty,
        };

        var name = principal.GetClaim(Claims.Name);
        if (!string.IsNullOrEmpty(name))
        {
            response[Claims.Name] = name;
        }

        if (principal.HasScope(Scopes.Email))
        {
            var email = principal.GetClaim(Claims.Email);
            if (!string.IsNullOrEmpty(email))
            {
                response[Claims.Email] = email;
            }
        }

        if (principal.HasScope(Scopes.Profile))
        {
            var nickname = principal.GetClaim(PandaAuthClaims.Nickname);
            if (!string.IsNullOrEmpty(nickname))
            {
                response[PandaAuthClaims.Nickname] = nickname;
            }
        }

        // 角色只在客户端显式申请 roles scope 时披露：CreatePrincipalAsync 会把用户全部角色写入
        // 令牌主体，若无条件回显，任何持 Access Token 的客户端都能读到角色，超出最小披露。
        if (principal.HasScope(Scopes.Roles))
        {
            var roles = principal.FindAll(Claims.Role).Select(claim => claim.Value).ToArray();
            if (roles.Length > 0)
            {
                response[Claims.Role] = roles;
            }
        }

        return Ok(response);
    }

    [HttpGet("logout")]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        // 尽力注销本地登录 Cookie；OpenIddict 负责校验 post_logout_redirect_uri 并完成协议层登出。
        if (User.Identity?.IsAuthenticated == true)
        {
            await signInManager.SignOutAsync(HttpContext);
        }

        return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // internal 而非 private：签发给 AT 的声明集合属对外契约（角色受 roles scope 约束），需要可测。
    internal async Task<ClaimsPrincipal> CreatePrincipalAsync(PandaUser user, ImmutableArray<string> scopes,
        ClaimsPrincipal? mfaSource = null, string authenticationTimeClaim = LoginSessionService.AuthenticatedAtClaim)
    {
        // Callers select only the validated login-cookie or OpenIddict-ticket claim, explicitly.
        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

        identity.AddClaim(new Claim(Claims.Subject, user.Id));
        identity.AddClaim(new Claim(Claims.Name, user.UserName ?? user.Id));
        // 人类主体事实（subject_type=human + 标准 auth_time 整秒）经 FleetHumanPrincipalClaims 从
        // 受信登录凭据继承；缺失/畸形/重复即抛出（上层转 invalid grant），绝不回退合成 "now"。
        identity.AddClaims(FleetHumanPrincipalClaims.Build(mfaSource, authenticationTimeClaim));

        if (tenantContextAccessor.Current is { } tenant)
        {
            identity.AddClaim(new Claim(PandaAuthClaims.TenantId, tenant.TenantId.Value));
            identity.AddClaim(new Claim(PandaAuthClaims.TenantHost, tenant.CanonicalHost));
        }

        // MFA 事实只从已验签的 IDP Cookie 或 OpenIddict 票据继承，绝不读取客户端参数。
        if (mfaSource?.FindFirst(MfaClaimTypes.Method)?.Value is { Length: > 0 } method &&
            mfaSource.FindFirst(MfaClaimTypes.VerifiedAt)?.Value is { Length: > 0 } verifiedAt)
        {
            identity.AddClaim(new Claim(MfaClaimTypes.Method, method));
            identity.AddClaim(new Claim(MfaClaimTypes.VerifiedAt, verifiedAt));
        }

        if (scopes.Contains(Scopes.Profile))
        {
            identity.AddClaim(new Claim(PandaAuthClaims.Nickname, user.Nickname ?? user.UserName ?? string.Empty));
        }

        if (scopes.Contains(Scopes.Email) && !string.IsNullOrEmpty(user.Email))
        {
            identity.AddClaim(new Claim(Claims.Email, user.Email));
        }

        // 角色写入 Access Token 受 roles scope 约束（最小披露）：AT 只交给自身受众，但无条件携带角色
        // 会让**未申请该 scope** 的客户端也从内省结果读到角色。
        // **契约**：资源服务器若需从 AT 读取角色，其客户端必须申请 `roles` scope。
        // 工作区内消费方（panda-auth-me、Server 的 DemoClient）均已申请，故行为不变。
        //
        // 另注：本服务签发的 AT 是**加密的 JWE**（OpenIddict 注册了加密密钥），载荷不可直接解码；
        // 资源服务器应经 `/connect/introspect` 读取声明（需授予该客户端内省权限），而不是解 JWT。
        if (scopes.Contains(Scopes.Roles))
        {
            var roles = await userManager.GetRolesAsync(user);
            identity.AddClaims(roles.Select(role => new Claim(Claims.Role, role)));
        }

        identity.AddClaims(await claimsPolicy.GetClaimsAsync(user, scopes.ToHashSet(StringComparer.Ordinal)));

        identity.SetScopes(scopes);
        // audience 与机器主体同规:scope 实体的 Resources(fleet.* → fleet-api、mgmt.* → panda-mgmt-api)
        // 随令牌投影,资源服务器据此校验受众;缺失会让人类令牌内省结果不含 aud
        // (OpenIddict ID2093「doesn't contain any audience」),资源服务器一律 401。
        identity.SetResources(await scopeManager.ListResourcesAsync(scopes, HttpContext.RequestAborted).ToListAsync(HttpContext.RequestAborted));

        var principal = new ClaimsPrincipal(identity);
        principal.SetDestinations(claim => claim.Type switch
        {
            // auth_time 与 subject_type 是控制面 introspection 契约面：必须随 AT 投影到内省结果。
            Claims.AuthenticationTime or PandaAuthClaims.SubjectType => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Name when principal.HasScope(Scopes.Profile) => [Destinations.AccessToken, Destinations.IdentityToken],
            _ => [Destinations.AccessToken],
        });
        return principal;
    }

    private IActionResult InvalidGrant(string description)
        => Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    /// <summary>
    /// max_age 是否要求重新认证。OIDC 语义：认证年龄（now − auth_time）超过 max_age 秒须重认证；
    /// max_age=0 是「任何既有认证都不可复用」的显式写法，恒为真。internal 供单测钉住边界语义。
    /// </summary>
    internal static bool ExceedsMaxAge(long? maxAge, long authenticatedAtSeconds, long nowSeconds)
        => maxAge is { } limit && (limit == 0 || nowSeconds - authenticatedAtSeconds > limit);
}
