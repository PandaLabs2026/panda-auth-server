using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using PandaAuth.Server.Features.PortalClients;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PortalReadOnlyProcessFactAttribute : FactAttribute
{
    public PortalReadOnlyProcessFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("PANDA_AUTH_PROOF_TEST_IMAGE") is null ||
            Environment.GetEnvironmentVariable("PANDA_AUTH_PROOF_TEST_NETWORK") is null ||
            Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES") is null)
            Skip = "Requires explicitly provisioned disposable Portal proof container and PostgreSQL.";
    }
}

public class PortalReadOnlyProcessTests
{
    [PortalReadOnlyProcessFact]
    public async Task ActualProcess_ReadOnlyProviderReturnsExistingProofWithoutAuditOrMutation()
    {
        var admin = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_POSTGRES"));
        PostgresTestBoundary.ValidateEndpoint(admin, false);
        Assert.Equal("postgres", admin.Database);
        admin.Database = "panda_auth_t0000";
        using var provider = PortalClientCommand.Services(admin.ConnectionString);
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
        await db.Database.MigrateAsync();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var descriptor = PortalClientRequest.Descriptor("isolated-proof-client");
        if (await manager.FindByClientIdAsync("isolated-proof-client") is null)
            await manager.CreateAsync(descriptor);
        await db.Database.ExecuteSqlRawAsync("GRANT SELECT ON ALL TABLES IN SCHEMA public TO panda_auth_t0000_runtime");
        var raw = PortalClientRegistrationPostgresTests.Request("isolated-proof-client");
        var proof = await RunAsync(raw, "pandalabs-postgres");
        Assert.True(proof.ExitCode == 0, "isolated proof process: " + proof.Error);
        using var json = JsonDocument.Parse(proof.Output);
        Assert.Equal("verified-existing", json.RootElement.GetProperty("result").GetString());
        Assert.Equal(PortalClientRequest.Hash(raw), json.RootElement.GetProperty("requestDigest").GetString());
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
        Assert.Equal(0, await db.AdminAuditLogs.CountAsync());
        var rejected = await RunAsync(raw, "wrong-host");
        Assert.NotEqual(0, rejected.ExitCode);
        Assert.Empty(rejected.Output);
        Assert.Equal(1, await db.Set<OpenIddictEntityFrameworkCoreApplication>().CountAsync());
        Assert.Equal(0, await db.AdminAuditLogs.CountAsync());
    }

    private static async Task<(int ExitCode,string Output,string Error)> RunAsync(byte[] request,string host)
    {
        var root=Path.GetFullPath("../../../../../",AppContext.BaseDirectory);
        var binary=Environment.GetEnvironmentVariable("PANDA_AUTH_PROOF_TEST_BINARY") ?? Path.Combine(root,"src/PandaAuth.Server/bin/Debug/net10.0");
        var start=new ProcessStartInfo("docker") { RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true };
        foreach(var arg in new[]{"run","--rm","-i","--label","cc.pandalabs.task=portal-auth-readonly-20261027",
            "--network",Environment.GetEnvironmentVariable("PANDA_AUTH_PROOF_TEST_NETWORK")!,"--user","1003:1003",
            "--read-only","--cap-drop","ALL","--security-opt","no-new-privileges",
            "--mount","type=bind,src="+binary+",dst=/app,readonly","--workdir","/app",
            "-e","ASPNETCORE_ENVIRONMENT=Production","-e","Auth__Issuer="+PortalClientRequest.Issuer,
            "-e","ConnectionStrings__Default=Host="+host+";Port=5432;Database=panda_auth_t0000;Username=panda_auth_t0000_runtime",
            "--entrypoint","dotnet",Environment.GetEnvironmentVariable("PANDA_AUTH_PROOF_TEST_IMAGE")!,"PandaAuth.Server.dll","--verify-portal-client"}) start.ArgumentList.Add(arg);
        using var process=Process.Start(start)!;
        await process.StandardInput.BaseStream.WriteAsync(request);process.StandardInput.Close();
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(45));
        var stderr=await error;
        Assert.DoesNotContain("ConnectionStrings__Default",stderr,StringComparison.Ordinal);
        return(process.ExitCode,await output,stderr);
    }
}
