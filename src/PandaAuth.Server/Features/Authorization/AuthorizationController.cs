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
    TenantRedirectPolicy tenantRedirectPolicy) : Controller
{
    [HttpGet("authorize")]
    [Authorize]
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
            return Challenge(
                new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString },
                LoginSessionService.Scheme);
        }

        // Legacy or malformed cookies must establish a new real login, never synthesize "now".
        if (!TryReadAuthenticationTime(authResult.Principal, LoginSessionService.AuthenticatedAtClaim, out _))
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
            !TryReadAuthenticationTime(authResult.Principal, Claims.AuthenticationTime, out _))
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
        if (!TryReadAuthenticationTime(mfaSource, authenticationTimeClaim, out var authenticatedAt))
            throw new InvalidOperationException("A valid original authentication time is required.");

        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

        identity.AddClaim(new Claim(Claims.Subject, user.Id));
        identity.AddClaim(new Claim(Claims.Name, user.UserName ?? user.Id));
        identity.AddClaim(new Claim(Claims.AuthenticationTime,
            authenticatedAt.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));

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

        var principal = new ClaimsPrincipal(identity);
        principal.SetDestinations(claim => claim.Type switch
        {
            Claims.AuthenticationTime => [Destinations.IdentityToken],
            Claims.Name when principal.HasScope(Scopes.Profile) => [Destinations.AccessToken, Destinations.IdentityToken],
            _ => [Destinations.AccessToken],
        });
        return principal;
    }

    private static bool TryReadAuthenticationTime(ClaimsPrincipal? source, string claimType, out long seconds)
    {
        seconds = 0;
        var claims = source?.FindAll(claimType).Take(2).ToArray();
        return claims is { Length: 1 } &&
            long.TryParse(claims[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) &&
            seconds is >= 0 and <= 253_402_300_799;
    }

    private IActionResult InvalidGrant(string description)
        => Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
