using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PandaAuth.Shared;
using PandaAuth.Server.Domain;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Server.Features.Authorization;

[Route("~/connect")]
public sealed class AuthorizationController(
    UserManager<PandaAuthUser> userManager,
    SignInManager<PandaAuthUser> signInManager) : Controller
{
    [HttpGet("authorize")]
    [Authorize]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("无法解析 OIDC 授权请求。");

        var authResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (authResult is not { Succeeded: true })
        {
            return Challenge(
                new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString },
                IdentityConstants.ApplicationScheme);
        }

        var user = await userManager.GetUserAsync(authResult.Principal!);
        if (user is null || user.Status != UserStatus.Active)
        {
            await signInManager.SignOutAsync();
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "账号不存在或已被冻结。",
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var principal = await CreatePrincipalAsync(user, request.GetScopes());

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

            var clientPrincipal = new ClaimsPrincipal(clientIdentity);
            clientPrincipal.SetDestinations(static _ => [Destinations.AccessToken]);

            return SignIn(clientPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // 授权码 / 刷新令牌：从票据中恢复用户并校验账号状态（冻结/注销立即失效）。
        var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

        var principal = await CreatePrincipalAsync(user, authResult.Principal!.GetScopes());
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
            var nickname = principal.GetClaim("nickname");
            if (!string.IsNullOrEmpty(nickname))
            {
                response["nickname"] = nickname;
            }
        }

        var roles = principal.FindAll(Claims.Role).Select(claim => claim.Value).ToArray();
        if (roles.Length > 0)
        {
            response[Claims.Role] = roles;
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
            await signInManager.SignOutAsync();
        }

        return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<ClaimsPrincipal> CreatePrincipalAsync(PandaAuthUser user, ImmutableArray<string> scopes)
    {
        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

        identity.AddClaim(new Claim(Claims.Subject, user.Id));
        identity.AddClaim(new Claim(Claims.Name, user.UserName ?? user.Id));

        if (scopes.Contains(Scopes.Profile))
        {
            identity.AddClaim(new Claim("nickname", user.Nickname ?? user.UserName ?? string.Empty));
        }

        if (scopes.Contains(Scopes.Email) && !string.IsNullOrEmpty(user.Email))
        {
            identity.AddClaim(new Claim(Claims.Email, user.Email));
        }

        var roles = await userManager.GetRolesAsync(user);
        identity.AddClaims(roles.Select(role => new Claim(Claims.Role, role)));

        identity.SetScopes(scopes);

        var principal = new ClaimsPrincipal(identity);
        principal.SetDestinations(static _ => [Destinations.AccessToken]);
        return principal;
    }

    private IActionResult InvalidGrant(string description)
        => Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
