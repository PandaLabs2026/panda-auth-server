using System.Net;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Features.Profile;
using PandaAuth.Server.Infrastructure.Persistence;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class OrganizationProfileProtocolTests
{
    private const string Client = "organization-profile-fixture";

    [PostgresFact]
    public async Task Selection_is_private_revision_bound_account_isolated_and_restore_safe()
    {
        var directory = Directory.CreateTempSubdirectory("org-profile-protocol-").FullName;
        var secret = Path.Combine(directory, "caller.secret");
        File.WriteAllText(secret, "synthetic-org-profile-service-secret-0000000");
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(secret, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        try
        {
            var organization = Guid.NewGuid();
            var settings = new Dictionary<string, string>
            {
                ["Auth:Issuer"] = "https://auth.org.fixture.test/", ["Profile:Enabled"] = "true",
                ["Profile:OrganizationsEnabled"] = "true", ["Profile:AllowedClients:0"] = Client,
                ["Profile:Oasis:Enabled"] = "true", ["Profile:Oasis:Issuer"] = "https://auth.org.fixture.test/",
                ["Profile:Oasis:Endpoint"] = "https://oasis.org.fixture.test/api/integrations/panda-auth/v1/profile-access",
                ["Profile:Oasis:ClientId"] = "organization-profile-service", ["Profile:Oasis:ClientSecretFile"] = secret,
                ["Profile:Oasis:OrganizationKeys:0"] = organization.ToString("D"),
            };
            await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: settings);
            await fixture.RegisterClientAsync(Client, ProfileScopes.Read, ProfileScopes.Resource);
            using (var scope = fixture.Host.Services.CreateScope())
            {
                var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
                await scopes.CreateAsync(new OpenIddictScopeDescriptor { Name = ProfileScopes.Write, Resources = { ProfileScopes.Resource } });
                var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                var application = (await apps.FindByClientIdAsync(Client))!;
                var descriptor = new OpenIddictApplicationDescriptor();
                await apps.PopulateAsync(descriptor, application);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + ProfileScopes.Write);
                await apps.UpdateAsync(application, descriptor);
            }
            using var browser = fixture.Browser();
            browser.BaseAddress = new Uri("https://auth.org.fixture.test/");
            var tokens = await fixture.IssueAsync(browser, Client, "openid " + ProfileScopes.Read + " " + ProfileScopes.Write);
            browser.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
            var path = PandaAuthProfileApi.SelfOrganization.Replace("{organizationKey}", organization.ToString("D"), StringComparison.Ordinal);
            using var read = await browser.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            Assert.True(read.Headers.CacheControl?.NoStore);
            var initial = await read.Content.ReadFromJsonAsync<ProfileOrganizationSelectionDto>();
            Assert.NotNull(initial);
            Assert.Empty(initial.Fields);
            Assert.Equal("\"0\"", initial.Revision);
            async Task<HttpResponseMessage> Put(string revision, string[] fields)
            {
                using var request = new HttpRequestMessage(HttpMethod.Put, path) { Content = JsonContent.Create(new { fields }) };
                request.Headers.TryAddWithoutValidation("If-Match", revision);
                return await browser.SendAsync(request);
            }
            using (var missingRevision = await browser.PutAsJsonAsync(path, new { fields = Array.Empty<string>() }))
                Assert.Equal((HttpStatusCode)428, missingRevision.StatusCode);
            foreach (var body in new[] { "{\"fields\":[\"roles\"]}", "{\"fields\":[\"avatar\",\"avatar\"]}",
                "{\"fields\":[],\"subject\":\"another-account\"}" })
            {
                using var invalid = new HttpRequestMessage(HttpMethod.Put, path)
                {
                    Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
                };
                invalid.Headers.TryAddWithoutValidation("If-Match", initial.Revision);
                using var rejected = await browser.SendAsync(invalid);
                Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
                Assert.True(rejected.Headers.CacheControl?.NoStore);
            }
            var memberPath = PandaAuthProfileApi.OrganizationMember.Replace("{organizationKey}", organization.ToString("D"), StringComparison.Ordinal)
                .Replace("{memberKey}", Guid.NewGuid().ToString("D"), StringComparison.Ordinal);
            foreach (var query in new[] { "", "?fields=roles", "?fields=avatar&fields=displayName", "?fields=avatar&subject=another-account" })
            {
                using var invalidQuery = await browser.GetAsync(memberPath + query);
                Assert.Equal(HttpStatusCode.BadRequest, invalidQuery.StatusCode);
                Assert.True(invalidQuery.Headers.CacheControl?.NoStore);
            }
            using var publish = await Put(initial.Revision, new[] { "avatar", "biography" });
            Assert.Equal(HttpStatusCode.OK, publish.StatusCode);
            var selected = await publish.Content.ReadFromJsonAsync<ProfileOrganizationSelectionDto>();
            Assert.NotNull(selected);
            Assert.Equal(new[] { "avatar", "biography" }, selected.Fields);
            Assert.NotEqual(initial.Revision, selected.Revision);
            using var stale = await Put(initial.Revision, new[] { "contactEmail" });
            Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
            using var revoke = await Put(selected.Revision, Array.Empty<string>());
            Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
            var revoked = await revoke.Content.ReadFromJsonAsync<ProfileOrganizationSelectionDto>();
            Assert.NotNull(revoked);
            Assert.Empty(revoked.Fields);
            Assert.NotEqual(initial.Revision, revoked.Revision);
            using var aba = await Put(initial.Revision, new[] { "avatar" });
            Assert.Equal(HttpStatusCode.PreconditionFailed, aba.StatusCode);
            using var otherOrganization = await browser.GetAsync(PandaAuthProfileApi.SelfOrganization.Replace("{organizationKey}", Guid.NewGuid().ToString("D"), StringComparison.Ordinal));
            Assert.Equal(HttpStatusCode.NotFound, otherOrganization.StatusCode);
            using var cookieOnly = fixture.Browser();
            cookieOnly.BaseAddress = browser.BaseAddress;
            using var anonymous = await cookieOnly.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            Assert.True(anonymous.Headers.CacheControl?.NoStore);
            var otherUser = Guid.NewGuid().ToString();
            using (var scope = fixture.Host.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                db.Users.Add(new PandaUser { Id = otherUser });
                db.UserProfiles.Add(new UserProfile { UserId = otherUser, Revision = new string('c', 32) });
                await db.SaveChangesAsync();
                var service = scope.ServiceProvider.GetRequiredService<OrganizationProfileService>();
                await service.WriteSelectionAsync(otherUser, organization, "\"0\"", new[] { "contactEmail" }, "storage-isolation", CancellationToken.None);
                Assert.Equal(new string('c', 32), (await db.UserProfiles.AsNoTracking().SingleAsync(p => p.UserId == otherUser)).Revision);
            }
            async Task<bool> Compete(string[] fields)
            {
                await using var scope = fixture.Host.Services.CreateAsyncScope();
                var service = scope.ServiceProvider.GetRequiredService<OrganizationProfileService>();
                try { await service.WriteSelectionAsync(fixture.UserId, organization, revoked.Revision, fields, "selection-race", CancellationToken.None); return true; }
                catch (ProfileOperationException e) when (e.StatusCode == 412) { return false; }
            }
            var outcomes = await Task.WhenAll(Compete(new[] { "avatar" }), Compete(new[] { "biography" }));
            Assert.Single(outcomes, success => success);
            await using (var scope = fixture.Host.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                var rows = await db.ProfileOrganizationVisibilities.AsNoTracking().Where(v => v.OrganizationKey == organization).ToListAsync();
                Assert.Equal(2, rows.Count);
                Assert.Equal(8, rows.Single(v => v.UserId == otherUser).Fields);
                Assert.Contains(rows.Single(v => v.UserId == fixture.UserId).Fields, new[] { 2, 4 });
            }
            await RestoreSelectionAsync(fixture.ConnectionString, organization, otherUser, directory);
        }
        finally { Directory.Delete(directory, true); }
    }
    [PostgresFact]
    public async Task Organization_routes_are_private_and_disabled_when_only_self_profiles_are_enabled()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync(settings: new Dictionary<string, string>
        {
            ["Profile:Enabled"] = "true",
        });
        using var browser = fixture.Browser();
        var organization = Guid.NewGuid().ToString("D");
        var member = Guid.NewGuid().ToString("D");
        foreach (var (method, route) in new[]
        {
            (HttpMethod.Get, PandaAuthProfileApi.SelfOrganization), (HttpMethod.Put, PandaAuthProfileApi.SelfOrganization),
            (HttpMethod.Get, PandaAuthProfileApi.OrganizationMember), (HttpMethod.Get, PandaAuthProfileApi.OrganizationAvatar),
        })
        {
            var path = route.Replace("{organizationKey}", organization, StringComparison.Ordinal)
                .Replace("{memberKey}", member, StringComparison.Ordinal);
            using var request = new HttpRequestMessage(method, path);
            using var response = await browser.SendAsync(request);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore);
        }
    }

    private static async Task RestoreSelectionAsync(string source, Guid organization, string otherUser, string directory)
    {
        var builder = new NpgsqlConnectionStringBuilder(source);
        PostgresTestBoundary.ValidateEndpoint(builder, PostgresTestBoundary.SharedMode);
        var restoreName = "panda_protocol_test_" + Guid.NewGuid().ToString("N");
        var admin = new NpgsqlConnectionStringBuilder(builder.ConnectionString) { Database = "postgres" };
        await using var connection = new NpgsqlConnection(admin.ConnectionString);
        await connection.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE DATABASE \"{restoreName}\"", connection)) await create.ExecuteNonQueryAsync();
        var target = new NpgsqlConnectionStringBuilder(builder.ConnectionString) { Database = restoreName };
        try
        {
            var backup = Path.Combine(directory, "selection.dump");
            await NativeAsync("pg_dump", builder, "--format=custom", "--file=" + backup);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(backup, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await NativeAsync("pg_restore", target, "--no-owner", "--no-acl", "--exit-on-error", backup);
            await using var restored = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>().UseNpgsql(target.ConnectionString).UseOpenIddict().Options);
            Assert.Empty(await restored.Database.GetPendingMigrationsAsync());
            var rows = await restored.ProfileOrganizationVisibilities.AsNoTracking().Where(v => v.OrganizationKey == organization).ToListAsync();
            Assert.Equal(2, rows.Count);
            Assert.Equal(8, rows.Single(v => v.UserId == otherUser).Fields);
            Assert.All(rows, row => Assert.Equal(32, row.Revision.Length));
            await restored.Users.Where(u => u.Id == otherUser).ExecuteDeleteAsync();
            Assert.Single(await restored.ProfileOrganizationVisibilities.Where(v => v.OrganizationKey == organization).ToListAsync());
        }
        finally { await PostgresTestBoundary.DropOwnedDatabaseAsync(target.ConnectionString, "panda_protocol_test_"); }
    }

    private static async Task NativeAsync(string executable, NpgsqlConnectionStringBuilder connection, params string[] arguments)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in new[] { "--host=" + connection.Host, "--port=" + connection.Port, "--username=" + connection.Username,
            "--dbname=" + connection.Database, "--no-password" }.Concat(arguments)) start.ArgumentList.Add(argument);
        foreach (var key in start.Environment.Keys.Where(key => key.StartsWith("PG", StringComparison.Ordinal)).ToArray()) start.Environment.Remove(key);
        start.Environment["PGPASSFILE"] = Path.Combine(Path.GetTempPath(), "unused-pgpass-" + Guid.NewGuid().ToString("N"));
        if (!string.IsNullOrEmpty(connection.Password)) start.Environment["PGPASSWORD"] = connection.Password;
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); throw; }
        await Task.WhenAll(stdout, stderr);
        Assert.True(process.ExitCode == 0, executable + " failed with exit " + process.ExitCode);
    }
}
