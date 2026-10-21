using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIddictClientAspNetCoreDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "PandaAuth.DemoClient";
        options.Cookie.SameSite = SameSiteMode.Lax;
    });

builder.Services.AddOpenIddict()
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();
        options.AllowRefreshTokenFlow();
        // The demo keeps tokens in its protected authentication ticket, not an
        // OpenIddict database. Ephemeral state keys are suitable for this local,
        // single-process sample; restarting invalidates pending login state.
        options.DisableTokenStorage();
        options.AddEphemeralEncryptionKey();
        options.AddEphemeralSigningKey();
        options.UseSystemNetHttp();
        var aspNetCore = options.UseAspNetCore()
            .EnableRedirectionEndpointPassthrough()
            .EnablePostLogoutRedirectionEndpointPassthrough()
            .EnableErrorPassthrough();
        // The documented sample callback is HTTP loopback. Never relax the
        // HTTPS requirement outside the local Development environment.
        if (builder.Environment.IsDevelopment())
            aspNetCore.DisableTransportSecurityRequirement();

        options.AddRegistration(new OpenIddictClientRegistration
        {
            ProviderName = "pandaauth",
            Issuer = new Uri(builder.Configuration["Auth:Issuer"] ?? "http://localhost:9004/"),
            ClientId = "demo-public",
            Scopes =
            {
                OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Scopes.Profile,
                OpenIddictConstants.Scopes.Email,
                OpenIddictConstants.Scopes.Roles,
                OpenIddictConstants.Scopes.OfflineAccess,
            },
            RedirectUri = new Uri("http://localhost:5201/callback/login/pandaauth"),
            PostLogoutRedirectUri = new Uri("http://localhost:5201/"),
        });
    });

var app = builder.Build();

app.MapControllers();

app.Run();

public partial class Program;
