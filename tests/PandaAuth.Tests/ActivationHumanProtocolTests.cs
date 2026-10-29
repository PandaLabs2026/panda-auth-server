using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using PandaAuth.ReadinessHarness;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ActivationHumanProtocolTests
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private static ActivationHumanInput Input() => new(1, "fleet", "admin", new string('a', 32), new string('b', 64),
        new string('c', 64), new string('d', 64), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1),
        "https://auth.appliket.com/", FirstPartyClients.AdminWeb, "fixture-client-secret",
        "https://auth.appliket.com/admin/callback/login/pandaauth", Actor("approved-admin", 'e'), Actor("approved-nonadmin", 'f'))
        { RuntimeConnection = "Host=127.0.0.1;Port=5432;Database=panda_auth_fleet;Username=panda_auth_fleet_runtime;Password=fixture-only",
          DatabaseFingerprint = new string('9', 64) };
    private static ActivationHumanIdentity Actor(string name, char subject) => new(name, "fixture-password",
        Convert.ToBase64String(new byte[20]), new string(subject, 64), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(name))));
    private static Dictionary<string, string> EnvironmentFor(ActivationHumanInput input, string line) => new()
    {
        ["PANDA_AUTH_ACTIVATION_POLICY_SHA256"] = input.PolicySha256,
        ["PANDA_AUTH_ACTIVATION_SOURCE_SHA256"] = input.SourceSha256,
        ["PANDA_AUTH_ACTIVATION_RUNTIMES_SHA256"] = input.RuntimesSha256,
        ["PANDA_AUTH_ACTIVATION_ATTEMPT"] = input.Attempt,
        ["PANDA_AUTH_ACTIVATION_DATABASE_FINGERPRINT"] = input.DatabaseFingerprint!,
        ["PANDA_AUTH_ACTIVATION_INPUT_SHA256"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(line)))
    };

    [Fact]
    public async Task MissingAuthorityCannotUseAnOriginalIssuerOrEmitAcceptance()
        => Assert.Equal(2, await ActivationHumanProtocol.Dispatch("{}"));

    [Fact]
    public async Task NativeBrowserChecksAuthorityBeforeAnyNetworkRequest()
    {
        using var browser = ProtocolUser.CreateBrowser(new Uri("https://auth.appliket.com/"), null, new CookieContainer(),
            _ => throw new InvalidOperationException("fixture-authority-lost"));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => browser.GetAsync("/connect/userinfo"));
        Assert.Equal("fixture-authority-lost", error.Message);
    }

    [Fact]
    public void ExactPrivateInputRequiresCallerPinsAndCannotChangeTheClientOrIdentity()
    {
        var input = Input();
        var line = JsonSerializer.Serialize(input, Json);
        var env = EnvironmentFor(input, line);
        Assert.Equal(input, ActivationHumanProtocol.Parse(line, key => env.GetValueOrDefault(key), DateTimeOffset.UtcNow));
        foreach (var changed in new[] { input with { ClientId = FirstPartyClients.MeWeb },
            input with { SourceSha256 = input.SourceSha256 + "\n" },
            input with { RuntimeConnection = "Host=foreign.invalid;Database=panda_auth_fleet;Username=panda_auth_fleet_runtime;Password=fixture-only" },
            input with { RuntimeConnection = input.RuntimeConnection + ";Options=-c role=postgres" },
            input with { Identity = Actor(" approved-admin ", 'e') },
            input with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) },
            input with { RedirectUri = "https://foreign.invalid/callback" },
            input with { Restricted = input.Identity } })
        {
            var payload = JsonSerializer.Serialize(changed, Json);
            var pins = EnvironmentFor(changed, payload);
            Assert.Throws<InvalidOperationException>(() => ActivationHumanProtocol.Parse(payload, key => pins.GetValueOrDefault(key), DateTimeOffset.UtcNow));
        }
        env["PANDA_AUTH_ACTIVATION_INPUT_SHA256"] = new string('0', 64);
        Assert.Throws<InvalidOperationException>(() => ActivationHumanProtocol.Parse(line, key => env.GetValueOrDefault(key), DateTimeOffset.UtcNow));
        env = EnvironmentFor(input, line);
        env["PANDA_AUTH_ACTIVATION_DATABASE_FINGERPRINT"] = new string('0', 64);
        Assert.Throws<InvalidOperationException>(() => ActivationHumanProtocol.Parse(line, key => env.GetValueOrDefault(key), DateTimeOffset.UtcNow));
    }

    [Fact]
    public void NativeInputCanCarryAFreshCodeWithoutExportingTheExistingFactor()
    {
        var input = Input();
        var document = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(input, Json))!;
        document["identity"]!["totpSecret"] = null;
        document["identity"]!["totpCode"] = "123456";
        document["identity"]!["totpCodeCreatedAt"] = DateTimeOffset.UtcNow;
        var line = document.ToJsonString();
        var env = EnvironmentFor(input, line);
        var parsed = ActivationHumanProtocol.Parse(line, key => env.GetValueOrDefault(key), DateTimeOffset.UtcNow);
        Assert.Equal(input.Identity.UserName, parsed.Identity.UserName);
    }

    [Fact]
    public void CodeInputCannotMixSeedsOrOmitItsBoundedTimestamp()
    {
        var input = Input();
        var identity = input.Identity with { TotpSecret = null, TotpCode = "123456", TotpCodeCreatedAt = DateTimeOffset.UtcNow };
        foreach (var changed in new[] { identity with { TotpSecret = input.Identity.TotpSecret },
            identity with { TotpCode = null }, identity with { TotpCodeCreatedAt = null },
            identity with { TotpCode = "１２３４５６" }, identity with { TotpCode = "12345 " },
            identity with { TotpCodeCreatedAt = input.CreatedAt.AddSeconds(-1) },
            identity with { TotpCodeCreatedAt = input.ExpiresAt } })
        {
            var payload = JsonSerializer.Serialize(input with { Identity = changed }, Json);
            var pins = EnvironmentFor(input, payload);
            Assert.Throws<InvalidOperationException>(() => ActivationHumanProtocol.Parse(payload, key => pins.GetValueOrDefault(key), DateTimeOffset.UtcNow));
        }
    }

    [Fact]
    public void CodeProviderRejectsExpiredFutureAndRepeatedUseWithoutReplayingMfa()
    {
        var issued = DateTimeOffset.UtcNow;
        var now = issued;
        var identity = Input().Identity with { TotpSecret = null, TotpCode = "123456", TotpCodeCreatedAt = issued };
        var code = ActivationHumanProtocol.CodeProvider(identity, () => now)!;
        Assert.Equal("123456", code());
        Assert.Throws<InvalidOperationException>(() => code());
        var delayed = ActivationHumanProtocol.CodeProvider(identity, () => now)!;
        now = issued.AddSeconds(30);
        Assert.Throws<InvalidOperationException>(() => delayed());
        Assert.Throws<InvalidOperationException>(() => ActivationHumanProtocol.CodeProvider(identity, () => now));
        now = issued.AddSeconds(-1);
        Assert.Throws<InvalidOperationException>(() => ActivationHumanProtocol.CodeProvider(identity, () => now));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SuppliedCodeStillRequiresNormalMfaResponseAndDoesNotDelayIntoAnotherStep(bool rejected)
    {
        var input = CoreInput("admin");
        input = input with { Identity = input.Identity with { TotpSecret = null, TotpCode = "123456", TotpCodeCreatedAt = DateTimeOffset.UtcNow } };
        var state = new ProtocolState { ExpectedManualCode = "123456", RejectManualCode = rejected };
        var waits = 0;
        Task<object> Run() => ActivationHumanProtocol.RunCoreAsync(input,
            cookies => new HttpClient(new ProtocolHandler(state, cookies)) { BaseAddress = new Uri(input.Issuer) },
            () => { }, _ => { waits++; return Task.CompletedTask; });
        if (rejected)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(Run);
            Assert.Equal(0, state.Logins);Assert.Equal(0, state.Revocations);Assert.Equal(0, waits);
        }
        else
        {
            var report = JsonSerializer.Serialize(await Run(), Json);
            Assert.DoesNotContain("123456", report);Assert.DoesNotContain("fixture-password", report);
            Assert.Equal(2, state.Logins);Assert.Equal(8, state.Revocations);
            Assert.Equal(1, waits); // Only the seed-based restricted actor waits.
            Assert.All(state.Sessions.Values, session => Assert.True(session.Revoked));
        }
    }

    [Fact]
    public async Task ExpiredCodeFailsBeforeSendingAnyActorCredentials()
    {
        var input = CoreInput("admin");
        input = input with { Identity = input.Identity with { TotpSecret = null, TotpCode = "123456", TotpCodeCreatedAt = DateTimeOffset.UtcNow.AddSeconds(-31) } };
        var browsers = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationHumanProtocol.RunCoreAsync(input,
            _ => { browsers++; throw new InvalidOperationException("must-not-open-browser"); }, () => { }));
        Assert.Equal(0, browsers);
    }

    [Fact]
    public async Task RevocationUsesOnlyTheTwoSuppliedSessionTokensAndFailsOnServiceErrors()
    {
        var handler = new RevocationHandler();
        using var browser = new HttpClient(handler) { BaseAddress = new Uri("https://auth.appliket.com/") };
        var snapshot = new SessionSnapshot(new string('a', 32), browser.BaseAddress.AbsoluteUri, 0, DateTimeOffset.UtcNow,
            [], "owned-fixture-access", "owned-fixture-refresh");
        await ActivationHumanProtocol.RevokeAsync(browser, Input(), snapshot);
        Assert.Equal(2, handler.Posts);
        handler.Status = HttpStatusCode.ServiceUnavailable;
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationHumanProtocol.RevokeAsync(browser, Input(), snapshot));
    }

    private sealed class RevocationHandler : HttpMessageHandler
    {
        public int Posts { get; private set; }
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal(PandaAuth.Shared.PandaAuthEndpoints.Revocation, request.RequestUri!.AbsolutePath);
            var form = await request.Content!.ReadAsStringAsync(cancellationToken);
            Assert.Contains("owned-fixture-", form);
            Assert.DoesNotContain("subject", form);
            Posts++;
            return new(Status);
        }
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("me")]
    public async Task FullComponentRequiresRealProtocolStatusesAndRejectionOfReplayedSessions(string component)
    {
        var input = CoreInput(component);
        var state = new ProtocolState();
        using var report = JsonDocument.Parse(JsonSerializer.Serialize(await ActivationHumanProtocol.RunCoreAsync(input,
            cookies => new HttpClient(new ProtocolHandler(state, cookies)) { BaseAddress = new Uri(input.Issuer) },
            () => { }, _ => Task.CompletedTask), Json));
        Assert.True(report.RootElement.GetProperty("valid").GetBoolean());
        Assert.Equal("activation-human-component", report.RootElement.GetProperty("scope").GetString());
        Assert.Equal(input.DatabaseFingerprint, report.RootElement.GetProperty("databaseFingerprint").GetString());
        Assert.DoesNotContain("fixture-password", report.RootElement.GetRawText());
        Assert.Equal(component == "admin" ? 2 : 1, state.Logins);
        Assert.All(state.Sessions.Values, session => Assert.True(session.Revoked));
        Assert.Equal(component == "admin" ? 8 : 4, state.Revocations);
    }

    [Fact]
    public async Task UnapprovedTokenSubjectIsNeverRevokedOrAccepted()
    {
        var state = new ProtocolState { WrongSubject = true };
        var input = CoreInput("admin");
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationHumanProtocol.RunCoreAsync(input,
            cookies => new HttpClient(new ProtocolHandler(state, cookies)) { BaseAddress = new Uri(input.Issuer) }, () => { }, _ => Task.CompletedTask));
        Assert.Equal(0, state.Revocations);
        Assert.Equal(1, state.Logins);
    }

    [Fact]
    public async Task SuccessfulRevocationStatusMustActuallyInvalidateTokensBeforeRpLogout()
    {
        var state = new ProtocolState { IgnoreRevocation = true };
        var input = CoreInput("me");
        await Assert.ThrowsAsync<InvalidOperationException>(() => ActivationHumanProtocol.RunCoreAsync(input,
            cookies => new HttpClient(new ProtocolHandler(state, cookies)) { BaseAddress = new Uri(input.Issuer) }, () => { }, _ => Task.CompletedTask));
    }

    private static ActivationHumanInput CoreInput(string component)
    {
        ActivationHumanIdentity Approved(string name) => Actor(name, 'e') with { SubjectSha256 = Hash("subject-" + name) };
        var input = Input() with { Identity = Approved("approved-admin"), Restricted = Approved("approved-nonadmin") };
        return component == "admin" ? input : input with { Component = component, ClientId = FirstPartyClients.MeWeb,
            RedirectUri = "https://auth.appliket.com/me/callback/login/pandaauth", Identity = input.Restricted!, Restricted = null };
    }

    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private sealed class Session(string name) { public string Name { get; } = name; public bool Revoked { get; set; } }
    private sealed class ProtocolState
    {
        public string? ExpectedManualCode { get; init; }
        public bool RejectManualCode { get; init; }
        public Dictionary<string, Session> Sessions { get; } = [];
        public Dictionary<string, string> Codes { get; } = [];
        public Dictionary<string, string> Access { get; } = [];
        public Dictionary<string, string> Refresh { get; } = [];
        public int Logins { get; set; }
        public int Revocations { get; set; }
        public bool WrongSubject { get; init; }
        public bool IgnoreRevocation { get; init; }
    }
    private sealed class ProtocolHandler(ProtocolState state, CookieContainer cookies) : HttpMessageHandler
    {
        private string pending = "";
        private static readonly Uri Owner = new("https://auth.appliket.com/");
        private void Cookie(string name, string value, string path = "/")
            => cookies.Add(Owner, new Cookie(name, value, path) { Secure = true, HttpOnly = true });
        private string Sid => cookies.GetAllCookies().Cast<Cookie>().FirstOrDefault(cookie => cookie.Name == "fixture-sso")?.Value ?? "";
        private bool Live(string sid) => state.Sessions.TryGetValue(sid, out var session) && !session.Revoked;
        private HttpResponseMessage Tokens(string sid)
        {
            var access = "access-" + Guid.NewGuid().ToString("N");
            var refresh = "refresh-" + Guid.NewGuid().ToString("N");
            state.Access[access] = sid; state.Refresh[refresh] = sid;
            return Body(new { access_token = access, refresh_token = refresh, expires_in = 600 });
        }
        private static HttpResponseMessage Body(object value, HttpStatusCode status = HttpStatusCode.OK)
            => new(status) { Content = new StringContent(JsonSerializer.Serialize(value)) };
        private static HttpResponseMessage Redirect(string path) => new(HttpStatusCode.Redirect)
            { Headers = { Location = new Uri(path, UriKind.RelativeOrAbsolute) } };
        private static HttpResponseMessage Page() => new(HttpStatusCode.OK)
            { Content = new StringContent("<input name=\"__RequestVerificationToken\" value=\"fixture-csrf\"/>") };

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            var query = QueryHelpers.ParseQuery(request.RequestUri.Query);
            var form = request.Content is null ? null : QueryHelpers.ParseQuery(await request.Content.ReadAsStringAsync(cancellationToken));
            if (path is "/admin/challenge" or "/me/login")
            {
                var component = path.StartsWith("/admin", StringComparison.Ordinal) ? "admin" : "me";
                return Redirect("/account/login?returnUrl=" + Uri.EscapeDataString("/connect/authorize?bff=" + component));
            }
            if (path == "/account/login")
            {
                if (request.Method == HttpMethod.Get) return Page();
                pending = form!["UserName"].ToString();
                return Redirect("/account/mfa/challenge");
            }
            if (path == "/account/mfa/challenge") return Page();
            if (path == "/account/mfa/challenge/totp")
            {
                if (pending == "approved-admin" && state.ExpectedManualCode is not null)
                {
                    Assert.Equal(state.ExpectedManualCode, form!["Code"].ToString());
                    if (state.RejectManualCode) return new(HttpStatusCode.BadRequest);
                }
                var sid = Guid.NewGuid().ToString("N"); state.Sessions[sid] = new(pending); state.Logins++;
                Cookie("fixture-sso", sid);
                return Redirect(form!["ReturnUrl"].ToString());
            }
            if (path == "/connect/authorize")
            {
                if (!Live(Sid)) return Redirect("/account/login");
                if (query.TryGetValue("bff", out var component)) { Cookie("fixture-" + component, Sid, "/" + component); return Redirect("/" + component + "/"); }
                var code = Guid.NewGuid().ToString("N"); state.Codes[code] = Sid;
                return Redirect(query["redirect_uri"] + "?code=" + code + "&state=" + query["state"]);
            }
            if (path == "/connect/token")
            {
                var code = form!["grant_type"] == "authorization_code";
                var source = code ? state.Codes : state.Refresh;
                if (!source.Remove(form[code ? "code" : "refresh_token"].ToString(), out var sid) || !Live(sid))
                    return Body(new { error = "invalid_grant" }, HttpStatusCode.BadRequest);
                return Tokens(sid);
            }
            if (path == "/connect/revoke")
            {
                var target = form!["token_type_hint"] == "access_token" ? state.Access : state.Refresh;
                if (!state.IgnoreRevocation) target.Remove(form["token"].ToString());
                state.Revocations++;
                return new(HttpStatusCode.OK);
            }
            if (path == "/connect/userinfo" || path.StartsWith("/admin-api/users/", StringComparison.Ordinal))
            {
                if (!state.Access.TryGetValue(request.Headers.Authorization?.Parameter ?? "", out var sid) || !Live(sid)) return new(HttpStatusCode.Unauthorized);
                if (path.StartsWith("/admin-api", StringComparison.Ordinal)) return new(state.Sessions[sid].Name == "approved-admin" ? HttpStatusCode.OK : HttpStatusCode.Forbidden);
                return Body(new { sub = state.WrongSubject ? "unapproved-subject" : "subject-" + state.Sessions[sid].Name });
            }
            if (path == "/account/change-password") return Live(Sid) ? Page() : Redirect("/account/login");
            if (path == "/account/logout") { state.Sessions[Sid].Revoked = true; return Redirect("/account/login"); }
            if (path.EndsWith("/api/session", StringComparison.Ordinal))
            {
                if (!Live(Sid)) return new(HttpStatusCode.Unauthorized);
                return Body(new { subject = "subject-" + state.Sessions[Sid].Name, roles = new[] { "admin" } });
            }
            if (path.EndsWith("/api/antiforgery", StringComparison.Ordinal)) return Body(new { token = "fixture-xsrf" });
            if (path.EndsWith("/api/logout", StringComparison.Ordinal))
            {
                Assert.Equal("fixture-xsrf", request.Headers.GetValues("X-XSRF-Token").Single());
                state.Sessions[Sid].Revoked = true; return Redirect("/connect/logout");
            }
            throw new InvalidOperationException("unexpected fixture endpoint");
        }
    }
}
