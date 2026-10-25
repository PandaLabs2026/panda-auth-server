using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.CloudConfig.JointFixture;
using Xunit;

namespace PandaAuth.Tests;

[CollectionDefinition("Security process isolation", DisableParallelization = true)]
public sealed class SecurityProcessCollection;

[Collection("Security process isolation")]
public sealed class AccountSecurityProcessTests
{
    [PostgresFact]
    public async Task TwoProcesses_ColdCreateOneKeySchedule_AndRestartReusesIt()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        await fixture.Host.DisposeAsync();
        await using (var db = fixture.Context()) await db.SigningKeys.ExecuteDeleteAsync();
        async Task<string[]> Refresh()
        {
            var start = new ProcessStartInfo("dotnet")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            foreach (var arg in new[] { "exec", "--runtimeconfig", Path.Combine(AppContext.BaseDirectory, "PandaAuth.Tests.runtimeconfig.json"),
                "--depsfile", Path.Combine(AppContext.BaseDirectory, "PandaAuth.Tests.deps.json"), typeof(FixtureEntry).Assembly.Location, "--signing-key-refresh-stdin" })
                start.ArgumentList.Add(arg);
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            try
            {
                await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new
                    { Connection = fixture.ConnectionString, UserId = fixture.UserId, BeforeCommit = false }));
                process.StandardInput.Close();
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(45));
                Assert.Equal(0, process.ExitCode);
                Assert.Equal("", await error);
                return JsonSerializer.Deserialize<string[]>(await output)!;
            }
            finally
            {
                if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
            }
        }
        var initial = await Task.WhenAll(Refresh(), Refresh());
        Assert.Equal(initial[0], initial[1]);
        Assert.Equal(3, initial[0].Length); // One unchanged encryption key, current signer and prepublished successor.
        Assert.Equal(initial[0], await Refresh());
        await using var verify = fixture.Context();
        Assert.Equal(3, await verify.SigningKeys.CountAsync());
    }

    [PostgresTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ProcessTermination_HasAtomicSecurityOutcome(bool beforeCommit)
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        string stamp;
        await using (var db = fixture.Context())
        {
            stamp = (await db.Users.SingleAsync(user => user.Id == fixture.UserId)).SecurityStamp!;
            db.Set<OpenIddictEntityFrameworkCoreToken>().Add(new()
                { Id = Guid.NewGuid().ToString(), Subject = fixture.UserId, Status = "valid", Type = "access_token" });
            await db.SaveChangesAsync();
        }
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var arg in new[] { "exec", "--runtimeconfig", Path.Combine(AppContext.BaseDirectory, "PandaAuth.Tests.runtimeconfig.json"),
            "--depsfile", Path.Combine(AppContext.BaseDirectory, "PandaAuth.Tests.deps.json"), typeof(FixtureEntry).Assembly.Location, "--account-security-stdin" })
            start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var error = process.StandardError.ReadToEndAsync();
        try
        {
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new
                { Connection = fixture.ConnectionString, UserId = fixture.UserId, BeforeCommit = beforeCommit }));
            process.StandardInput.Close();
            var phase = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(45));
            Assert.Equal(beforeCommit ? "before_commit" : "after_commit", phase);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
        }
        Assert.Equal("", await error);
        await using var verify = fixture.Context();
        var user = await verify.Users.SingleAsync(user => user.Id == fixture.UserId);
        Assert.Equal(beforeCommit, user.SecurityStamp == stamp);
        var token = await verify.Set<OpenIddictEntityFrameworkCoreToken>().SingleAsync(token => token.Subject == fixture.UserId);
        Assert.Equal(beforeCommit ? "valid" : "revoked", token.Status);
        Assert.Equal(beforeCommit ? 0 : 2, await verify.SecurityEvents.CountAsync());
    }
}
