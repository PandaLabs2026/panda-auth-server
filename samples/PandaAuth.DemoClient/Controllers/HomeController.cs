using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.DemoClient.Controllers;

/// <summary>
/// OIDC 登录闭环演示：授权码 + PKCE 登录 → profile 展示 → 刷新令牌 → 吊销 → RP 发起登出。
/// </summary>
public sealed class HomeController(OpenIddictClientService clientService, IConfiguration configuration) : Controller
{
    private const string ProviderName = "pandaauth";

    private Uri Issuer => new(configuration["Auth:Issuer"] ?? "http://localhost:9004/", UriKind.Absolute);

    [HttpGet("~/")]
    public IActionResult Index() => View();

    [HttpGet("~/login")]
    public IActionResult Login(string? returnUrl = null)
        => Challenge(new AuthenticationProperties
        {
            RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/profile",
        });

    [Authorize]
    [HttpGet("~/profile")]
    public async Task<IActionResult> Profile()
    {
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ViewData["HasAccessToken"] = result.Properties?.GetTokenValue("access_token") is not null;
        ViewData["HasRefreshToken"] = User.FindFirst("refresh_token") is not null;
        return View();
    }

    [Authorize]
    [HttpPost("~/refresh")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Refresh(CancellationToken cancellationToken)
    {
        var refreshToken = User.FindFirst("refresh_token")?.Value;
        if (string.IsNullOrEmpty(refreshToken))
        {
            return RedirectToAction(nameof(Profile));
        }

        var result = await clientService.AuthenticateWithRefreshTokenAsync(
            new OpenIddictClientModels.RefreshTokenAuthenticationRequest
            {
                Issuer = Issuer,
                ProviderName = ProviderName,
                RefreshToken = refreshToken,
                CancellationToken = cancellationToken,
            });

        await SignInWithTokensAsync(result.Principal, result.AccessToken, result.RefreshToken);
        return RedirectToAction(nameof(Profile));
    }

    [Authorize]
    [HttpPost("~/revoke")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(CancellationToken cancellationToken)
    {
        var refreshToken = User.FindFirst("refresh_token")?.Value;
        if (!string.IsNullOrEmpty(refreshToken))
        {
            await clientService.RevokeTokenAsync(new OpenIddictClientModels.RevocationRequest
            {
                Issuer = Issuer,
                ProviderName = ProviderName,
                Token = refreshToken,
                TokenTypeHint = "refresh_token",
                CancellationToken = cancellationToken,
            });
        }

        return SignOut(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [HttpPost("~/logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        // RP 发起登出：清空本地 Cookie 并跳转 /connect/logout。
        var properties = new AuthenticationProperties { RedirectUri = "/" };
        return SignOut(properties, CookieAuthenticationDefaults.AuthenticationScheme, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/callback/login/{provider}")]
    [HttpPost("~/callback/login/{provider}")]
    public async Task<IActionResult> CallbackLogin()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true } || result.Principal is null)
        {
            return RedirectToAction(nameof(Index));
        }

        var redirectUri = result.Properties.RedirectUri ?? "/profile";
        await SignInWithTokensAsync(result.Principal,
            result.Properties.GetTokenValue("access_token"),
            result.Properties.GetTokenValue("refresh_token"));

        return LocalRedirect(redirectUri);
    }

    private async Task SignInWithTokensAsync(ClaimsPrincipal remotePrincipal, string? accessToken, string? refreshToken)
    {
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
        identity.AddClaim(new Claim(Claims.Subject, remotePrincipal.GetClaim(Claims.Subject) ?? string.Empty));
        var name = remotePrincipal.GetClaim(Claims.Name);
        if (!string.IsNullOrEmpty(name))
        {
            identity.AddClaim(new Claim(Claims.Name, name));
        }
        var email = remotePrincipal.GetClaim(Claims.Email);
        if (!string.IsNullOrEmpty(email))
        {
            identity.AddClaim(new Claim(Claims.Email, email));
        }
        identity.AddClaims(remotePrincipal.FindAll(Claims.Role));

        var properties = new AuthenticationProperties { RedirectUri = "/profile" };
        var tokens = new List<AuthenticationToken>();
        if (accessToken is not null)
        {
            tokens.Add(new AuthenticationToken { Name = "access_token", Value = accessToken });
        }
        if (refreshToken is not null)
        {
            tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = refreshToken });
            identity.AddClaim(new Claim("refresh_token", refreshToken));
        }
        properties.StoreTokens(tokens);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), properties);
    }
}
