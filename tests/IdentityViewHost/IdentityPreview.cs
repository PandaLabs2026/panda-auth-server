using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.IdentityViewTests;

// Renders actual compiled product views. Never starts Server/DB/authentication or loads product configuration.
public static class IdentityPreview
{
    public static WebApplication Build(string root, Action<IWebHostBuilder>? configure = null)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions {
            ApplicationName = typeof(IdentityPreview).Assembly.GetName().Name,
            EnvironmentName = "Testing", ContentRootPath = root
        });
        builder.WebHost.UseKestrel();
        configure?.Invoke(builder.WebHost);
        builder.Services.AddLogging();
        builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        builder.Services.AddControllersWithViews()
            .AddApplicationPart(typeof(AccountController).Assembly);
        var app = builder.Build();
        // Retain production route metadata for real form action generation, but never execute those endpoints.
        app.Use(async (context, next) => {
            if (!context.Request.Path.StartsWithSegments("/fixture") &&
                !context.Request.Path.StartsWithSegments("/account/brand") && context.Request.Path != "/account/mfa.js") {
                context.Response.StatusCode = 404; return;
            }
            await next(context);
        });
        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseStaticFiles(new StaticFileOptions {
            FileProvider = new PhysicalFileProvider(Path.Combine(root, "src/PandaAuth.Server/wwwroot/brand")), RequestPath = "/account/brand"
        });
        app.UseStaticFiles(new StaticFileOptions {
            FileProvider = new PhysicalFileProvider(Path.Combine(root, "src/PandaAuth.Server/wwwroot/account")), RequestPath = "/account"
        });
        app.MapControllers();
        return app;
    }

    public static async Task Main(string[] args)
    {
        if (args.Length != 2) throw new ArgumentException("Expected Server repository root and fresh private metadata path.");
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = X509CertificateLoader.LoadPkcs12(request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1)).Export(X509ContentType.Pfx), null);
        await using var app = Build(Path.GetFullPath(args[0]), host => host.ConfigureKestrel(options =>
            options.Listen(IPAddress.Loopback, 0, endpoint => endpoint.UseHttps(certificate))));
        await app.StartAsync();
        var origin = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        using (var file = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write, FileShare.None))
            JsonSerializer.Serialize(file, new { origin, fixture = "server-identity-views" });
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(args[1], UnixFileMode.UserRead | UnixFileMode.UserWrite);
        await app.WaitForShutdownAsync();
    }
}

public sealed class IdentityPreviewController : Controller
{
    [HttpGet("/fixture/{page}")]
    public IActionResult Show(string page)
    {
        if (page.EndsWith("-error", StringComparison.Ordinal)) {
            ModelState.AddModelError(string.Empty, "无法完成本次操作，请检查输入后重试。Long validation message with no account information.");
            page = page[..^6];
        }
        const string target = "/me/security?tab=totp";
        (string View, object Model)? sample = page switch {
            "login" => ("Account/Login", new LoginViewModel { ReturnUrl = target }),
            "challenge" => ("LoginMfaChallenge/Index", new LoginMfaChallengeViewModel { HasTotp = true, HasRecoveryCodes = true, ReturnUrl = target }),
            "recovery" => ("LoginMfaChallenge/Index", new LoginMfaChallengeViewModel { HasRecoveryCodes = true, ReturnUrl = target }),
            "blocked" => ("LoginMfaChallenge/Blocked", new LoginMfaChallengeViewModel()),
            "mfa-enroll" => ("Mfa/Index", new MfaViewModel { ReturnUrl = target }),
            "mfa-assert" => ("Mfa/Index", new MfaViewModel { HasTotp = true, ReturnUrl = target }),
            "forgot" => ("Credential/ForgotPassword", new ForgotPasswordViewModel { ReturnUrl = target }),
            "reset" => ("Credential/ResetPassword", new ResetPasswordViewModel { ReturnUrl = target }),
            "change-password" => ("Credential/ChangePassword", new ChangePasswordViewModel { ReturnUrl = target }),
            "confirm-email" => ("Credential/ConfirmEmail", new ConfirmEmailViewModel()),
            "change-email" => ("Credential/ChangeEmail", new ChangeEmailViewModel { ReturnUrl = target }),
            "confirm-email-change" => ("Credential/ConfirmEmailChange", new ConfirmEmailChangeViewModel { ReturnUrl = target }),
            _ => null
        };
        return sample is {} item ? View("/Views/" + item.View + ".cshtml", item.Model) : NotFound();
    }
}
