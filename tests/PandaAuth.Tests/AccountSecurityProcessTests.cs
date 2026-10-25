using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.CloudConfig.JointFixture;
using Xunit;

namespace PandaAuth.Tests;

public sealed class AccountSecurityProcessTests
{
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
