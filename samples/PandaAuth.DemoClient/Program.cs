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
        options.UseAspNetCore()
            .EnableRedirectionEndpointPassthrough()
            .EnablePostLogoutRedirectionEndpointPassthrough()
            .EnableErrorPassthrough();

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
