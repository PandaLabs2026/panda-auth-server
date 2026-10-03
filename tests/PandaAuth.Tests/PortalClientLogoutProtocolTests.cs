using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.PortalClients;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public class PortalClientLogoutProtocolTests
{
    [PostgresFact]
    public async Task ActualRegisteredPublicDescriptor_LogoutWithoutHintClearsCookieAndRejectsForeignUri()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        await VerifyRegisteredPublicLogoutAsync(fixture, await fixture.Service.ExecuteAsync(PortalClientRegistrationPostgresTests.Request()));
    }
    internal static async Task VerifyRegisteredPublicLogoutAsync(RegistrationDatabase fixture, string originalReceipt)
    {
        using var receipt = JsonDocument.Parse(originalReceipt);
        var clientId = receipt.RootElement.GetProperty("clientId").GetString()!;
        await using var factory = new LogoutFactory(fixture.Connection);
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
            { AllowAutoRedirect = false, BaseAddress = new Uri(PortalClientRequest.Issuer) });
        var password = "Aa!9" + Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
        await using (var scope = factory.Services.CreateAsyncScope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(new PandaUser { UserName = "logout-fixture-user" }, password)).Succeeded);
        var loginPage = await browser.GetAsync("/account/login");
        var hidden = Regex.Match(await loginPage.Content.ReadAsStringAsync(), "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(hidden.Success);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(hidden.Groups[1].Value),
            ["UserName"] = "logout-fixture-user", ["Password"] = password, ["ReturnUrl"] = "/",
        });
        var login = await browser.PostAsync("/account/login", form);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Contains(login.Headers.GetValues("Set-Cookie"), v => v.StartsWith(LoginSessionService.Scheme + "=", StringComparison.Ordinal));
        var foreign = await browser.GetAsync("/connect/logout?client_id=" + clientId + "&post_logout_redirect_uri=https%3A%2F%2Fforeign.invalid%2Flogout");
        Assert.Equal(HttpStatusCode.BadRequest, foreign.StatusCode);
        Assert.Null(foreign.Headers.Location);
        var logout = await browser.GetAsync("/connect/logout?client_id=" + clientId + "&post_logout_redirect_uri=" + Uri.EscapeDataString(PortalClientRequest.LogoutCallback) + "&state=logout-proof-state");
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.Equal(PortalClientRequest.LogoutCallback + "?state=logout-proof-state", logout.Headers.Location!.AbsoluteUri);
        Assert.True(logout.Headers.TryGetValues("Set-Cookie", out var deleted) && deleted.Any(v => v.StartsWith(LoginSessionService.Scheme + "=;", StringComparison.Ordinal)));
        // A fresh authorization request now challenges login: no local IDP session survived.
        var challenge = await browser.GetAsync("/connect/authorize?client_id=" + clientId + "&redirect_uri=" + Uri.EscapeDataString(PortalClientRequest.Callback) +
            "&response_type=code&scope=openid&code_challenge_method=S256&code_challenge=" + new string('a', 43));
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.True(challenge.Headers.Location!.AbsoluteUri.Contains("/account/login", StringComparison.Ordinal));
    }
    private sealed class LogoutFactory(string connection) : WebApplicationFactory<Program>
    {
        private readonly ProtocolHostContentRoot _root = new(connection, new Dictionary<string, string>
        {
            ["Auth:Issuer"] = PortalClientRequest.Issuer, ["Auth:HttpsRequired"] = "false",
            ["Auth:Seed:Enabled"] = "false", ["Auth:DataProtectionKeyPath"] = "",
        });
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseContentRoot(_root.Path);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureTestServices(services => services.AddDataProtection().UseEphemeralDataProtectionProvider());
        }
        protected override void Dispose(bool disposing) { base.Dispose(disposing); _root.Dispose(); }
    }
}
