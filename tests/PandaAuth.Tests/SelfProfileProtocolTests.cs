using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Domain;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SelfProfileProtocolTests
{
    private const string Client = "profile-protocol-fixture";
    private static Dictionary<string, string> Enabled => new()
    {
        ["Profile:Enabled"] = "true", ["Profile:AllowedClients:0"] = Client,
    };

    [PostgresFact]
    public async Task Disabled_feature_returns_uniform_private_not_found_without_a_token()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        using var browser = fixture.Browser();
        foreach (var (method, path) in new[]
        {
            (HttpMethod.Get, PandaAuthProfileApi.Self), (HttpMethod.Patch, PandaAuthProfileApi.Self),
            (HttpMethod.Get, PandaAuthProfileApi.Avatar), (HttpMethod.Put, PandaAuthProfileApi.Avatar),
            (HttpMethod.Delete, PandaAuthProfileApi.Avatar), (HttpMethod.Delete, PandaAuthProfileApi.ContactEmail),
            (HttpMethod.Post, PandaAuthProfileApi.ContactEmailChallenges), (HttpMethod.Post, PandaAuthProfileApi.ContactEmailConfirmation),
        })
        {
            using var response = await browser.SendAsync(new HttpRequestMessage(method, path));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        }
    }

    [PostgresFact]
    public async Task Real_delegated_bearer_reads_and_edits_only_self_while_cookie_alone_is_rejected()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: Enabled);
        await RegisterReadWriteAsync(fixture);
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, Client, "openid roles " + ProfileScopes.Read + " " + ProfileScopes.Write);
        using (var cookieOnly = await browser.GetAsync(PandaAuthProfileApi.Self))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, cookieOnly.StatusCode);
            Assert.Equal("no-store", cookieOnly.Headers.CacheControl?.ToString());
        }
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        using var read = await browser.GetAsync(PandaAuthProfileApi.Self);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        Assert.Equal("no-store", read.Headers.CacheControl?.ToString());
        var empty = (await read.Content.ReadFromJsonAsync<SelfProfileDto>())!;
        Assert.Null(empty.DisplayName);
        Assert.Null(empty.ContactEmail.Address);
        Assert.Equal("\"0\"", read.Headers.ETag!.ToString());
        using (var db = fixture.Context()) Assert.Empty(await db.UserProfiles.ToListAsync());
        using var missing = await browser.PatchAsync(PandaAuthProfileApi.Self, Json("{\"displayName\":\"private\"}"));
        Assert.Equal((HttpStatusCode)428, missing.StatusCode);
        using var update = new HttpRequestMessage(HttpMethod.Patch, PandaAuthProfileApi.Self)
        {
            Content = Json("{\"displayName\":\"Private profile\",\"biography\":null}"),
        };
        update.Headers.TryAddWithoutValidation("If-Match", empty.Revision);
        using var saved = await browser.SendAsync(update);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        var dto = (await saved.Content.ReadFromJsonAsync<SelfProfileDto>())!;
        Assert.Equal("Private profile", dto.DisplayName);
        Assert.Equal(dto.Revision, saved.Headers.ETag!.ToString());
        Assert.Equal("no-store", saved.Headers.CacheControl?.ToString());
        using var stale = new HttpRequestMessage(HttpMethod.Patch, PandaAuthProfileApi.Self) { Content = Json("{\"displayName\":\"stale\"}") };
        stale.Headers.TryAddWithoutValidation("If-Match", "\"0\"");
        using var conflict = await browser.SendAsync(stale);
        Assert.Equal(HttpStatusCode.PreconditionFailed, conflict.StatusCode);
        using var immutable = new HttpRequestMessage(HttpMethod.Patch, PandaAuthProfileApi.Self) { Content = Json("{\"subject\":\"other\",\"displayName\":\"bad\"}") };
        immutable.Headers.TryAddWithoutValidation("If-Match", dto.Revision);
        using var rejected = await browser.SendAsync(immutable);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using (var db = fixture.Context())
        {
            Assert.Equal("Private profile", (await db.UserProfiles.SingleAsync()).DisplayName);
            Assert.Equal("security-admin@example.test", (await db.Users.SingleAsync()).Email);
            var other = new PandaUser();
            db.Users.Add(other);
            db.UserProfiles.Add(new UserProfile { UserId = other.Id, DisplayName = "other private profile", Revision = new string('d', 32) });
            await db.SaveChangesAsync();
            using var attemptedTarget = await browser.GetAsync(PandaAuthProfileApi.Self + "?subject=" + other.Id);
            Assert.Equal("Private profile", (await attemptedTarget.Content.ReadFromJsonAsync<SelfProfileDto>())!.DisplayName);
            await db.Users.Where(u => u.Id == fixture.UserId).ExecuteUpdateAsync(setters => setters.SetProperty(u => u.Status, UserStatus.Frozen));
        }
        using var frozen = await browser.GetAsync(PandaAuthProfileApi.Self);
        Assert.Equal(HttpStatusCode.Unauthorized, frozen.StatusCode);
        Assert.Equal("no-store", frozen.Headers.CacheControl?.ToString());
    }

    private sealed class ContactMail : PandaAuth.Server.Infrastructure.Messaging.IEmailSender
    {
        public string Token { get; private set; } = "";
        public Task SendAsync(string email, string subject, string html, CancellationToken ct) => throw new InvalidOperationException();
        public Task SendPasswordResetNoticeAsync(string email, CancellationToken ct) => throw new InvalidOperationException();
        public Task SendProfileContactVerificationAsync(string email, string token, Guid deliveryId, CancellationToken ct)
        { Token = token; return Task.CompletedTask; }
    }

    [PostgresFact]
    public async Task Contact_http_challenge_confirmation_and_delete_preserve_credentials_and_reject_unknown_fields()
    {
        var mail = new ContactMail();
        await using var fixture = await SecurityProtocolFixture.CreateAsync(
            services => services.AddSingleton<PandaAuth.Server.Infrastructure.Messaging.IEmailSender>(mail), Enabled);
        await RegisterReadWriteAsync(fixture);
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, Client, "openid roles " + ProfileScopes.Read + " " + ProfileScopes.Write);
        browser.DefaultRequestHeaders.Authorization = new("Bearer", tokens.GetProperty("access_token").GetString());
        using var missing = await browser.PostAsync(PandaAuthProfileApi.ContactEmailChallenges, Json("{\"address\":\"contact@example.invalid\"}"));
        Assert.Equal((HttpStatusCode)428, missing.StatusCode);
        using var unknown = new HttpRequestMessage(HttpMethod.Post, PandaAuthProfileApi.ContactEmailChallenges)
            { Content = Json("{\"address\":\"contact@example.invalid\",\"subject\":\"other\"}") };
        unknown.Headers.TryAddWithoutValidation("If-Match", "\"0\"");
        using var invalid = await browser.SendAsync(unknown);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using var create = new HttpRequestMessage(HttpMethod.Post, PandaAuthProfileApi.ContactEmailChallenges)
            { Content = Json("{\"address\":\"contact@example.invalid\"}") };
        create.Headers.TryAddWithoutValidation("If-Match", "\"0\"");
        using var pending = await browser.SendAsync(create);
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        Assert.Equal("no-store", pending.Headers.CacheControl?.ToString());
        var challenge = (await pending.Content.ReadFromJsonAsync<ProfileContactEmailChallengeResponse>())!;
        Assert.Equal(challenge.Profile.Revision, pending.Headers.ETag!.ToString());
        using var confirmed = await browser.PostAsJsonAsync(PandaAuthProfileApi.ContactEmailConfirmation,
            new ProfileContactEmailConfirmationRequest(challenge.ChallengeId, mail.Token));
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        var verified = (await confirmed.Content.ReadFromJsonAsync<SelfProfileDto>())!;
        Assert.Equal(ProfileContactEmailState.Verified, verified.ContactEmail.State);
        using var delete = new HttpRequestMessage(HttpMethod.Delete, PandaAuthProfileApi.ContactEmail);
        delete.Headers.TryAddWithoutValidation("If-Match", verified.Revision);
        using var removed = await browser.SendAsync(delete);
        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        Assert.Equal(ProfileContactEmailState.None, (await removed.Content.ReadFromJsonAsync<SelfProfileDto>())!.ContactEmail.State);
        using var db = fixture.Context();
        Assert.Equal("security-admin@example.test", (await db.Users.SingleAsync()).Email);
        Assert.Empty(await db.ProfileContactChallenges.ToListAsync());
    }

    [PostgresTheory]
    [InlineData("other-client", "profile.read", "profile-api")]
    [InlineData(Client, "profile.read", "other-api")]
    [InlineData(Client, "other.scope", "profile-api")]
    public async Task Delegated_resource_boundary_does_not_accept_role_scope_or_client_substitutes(string client, string scope, string audience)
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: Enabled);
        await fixture.RegisterClientAsync(client, scope, audience);
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, client, "openid roles " + scope);
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        using var response = await browser.GetAsync(PandaAuthProfileApi.Self);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [PostgresFact]
    public async Task Machine_token_from_an_allowed_client_cannot_use_private_profile()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: Enabled);
        await fixture.RegisterClientAsync(Client, ProfileScopes.Read, ProfileScopes.Resource);
        using (var scope = fixture.Host.Services.CreateScope())
        {
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = (await applications.FindByClientIdAsync(Client))!;
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, application);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            await applications.UpdateAsync(application, descriptor);
        }
        using var browser = fixture.Browser();
        using var tokenResponse = await browser.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = Client, ["client_secret"] = SecurityProtocolFixture.Secret,
            ["scope"] = ProfileScopes.Read, ["grant_type"] = "client_credentials",
        }));
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        using var token = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.RootElement.GetProperty("access_token").GetString());
        using var response = await browser.GetAsync(PandaAuthProfileApi.Self);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [PostgresFact]
    public async Task Foreign_issuer_token_is_rejected_even_with_the_same_database_keys()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: Enabled);
        await RegisterReadWriteAsync(fixture);
        var settings = Enabled;
        settings["Auth:Issuer"] = "https://foreign-issuer.invalid/";
        await using var foreign = new SecurityProtocolFixture.Factory(fixture.ConnectionString, null, settings);
        using var issuerBrowser = foreign.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://foreign-issuer.invalid/"), AllowAutoRedirect = false,
        });
        var tokens = await fixture.IssueAsync(issuerBrowser, Client, "openid roles " + ProfileScopes.Read);
        using var browser = fixture.Browser();
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        using var response = await browser.GetAsync(PandaAuthProfileApi.Self);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [PostgresFact]
    public async Task Invalid_json_and_chunked_body_limits_leave_the_profile_unmodified()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: Enabled);
        await RegisterReadWriteAsync(fixture);
        using var browser = fixture.Browser();
        var tokens = await fixture.IssueAsync(browser, Client, "openid roles " + ProfileScopes.Read + " " + ProfileScopes.Write);
        browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        foreach (var (json, status) in new[]
        {
            ("{}", 400), ("{\"displayName\":\"\"}", 422),
            ("{\"biography\":null,\"biography\":\"shadow\"}", 400),
            ("{\"displayName\":\"ok\",\"roles\":[\"admin\"]}", 400),
            ("{\"biography\":\"" + new string('x', 1001) + "\"}", 422),
        })
        {
            using var request = new HttpRequestMessage(HttpMethod.Patch, PandaAuthProfileApi.Self) { Content = Json(json) };
            request.Headers.TryAddWithoutValidation("If-Match", "\"0\"");
            using var response = await browser.SendAsync(request);
            Assert.Equal((HttpStatusCode)status, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        }
        using var oversized = new HttpRequestMessage(HttpMethod.Patch, PandaAuthProfileApi.Self)
            { Content = new StreamingJsonContent(new string(' ', 16385)) };
        oversized.Headers.TryAddWithoutValidation("If-Match", "\"0\"");
        using var rejected = await browser.SendAsync(oversized);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, rejected.StatusCode);
        Assert.Equal("no-store", rejected.Headers.CacheControl?.ToString());
        using var db = fixture.Context();
        Assert.Empty(await db.UserProfiles.ToListAsync());
    }

    private sealed class StreamingJsonContent : HttpContent
    {
        private readonly byte[] bytes;
        public StreamingJsonContent(string value)
        {
            bytes = Encoding.UTF8.GetBytes(value);
            Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(bytes).AsTask();
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }

    private static StringContent Json(string value) => new(value, Encoding.UTF8, "application/json");

    private static async Task RegisterReadWriteAsync(SecurityProtocolFixture fixture)
    {
        await fixture.RegisterClientAsync(Client, ProfileScopes.Read, ProfileScopes.Resource);
        using var scope = fixture.Host.Services.CreateScope();
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var descriptor = new OpenIddictScopeDescriptor { Name = ProfileScopes.Write };
        descriptor.Resources.Add(ProfileScopes.Resource);
        await scopes.CreateAsync(descriptor);
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = (await applications.FindByClientIdAsync(Client))!;
        var client = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(client, application);
        client.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + ProfileScopes.Write);
        await applications.UpdateAsync(application, client);
    }
}
