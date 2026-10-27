using System.Diagnostics;
using PandaAuth.Server.Features.PortalClients;
using Xunit;

namespace PandaAuth.Tests;

public class PortalClientCommandTests
{
    [Fact]
    public void ReadOnlyProof_IsAnExclusiveCommand()
    {
        Assert.Equal(3, PortalClientCommand.Mode(["--verify-portal-client"]));
        Assert.Equal(-1, PortalClientCommand.Mode(["--verify-portal-client", "--register-portal-client"]));
    }

    [Theory]
    [InlineData("pandalabs-postgres", "panda_auth_t0000", "panda_auth_t0000_runtime", true)]
    [InlineData("other-host", "panda_auth_t0000", "panda_auth_t0000_runtime", false)]
    [InlineData("pandalabs-postgres", "other-db", "panda_auth_t0000_runtime", false)]
    [InlineData("pandalabs-postgres", "panda_auth_t0000", "postgres", false)]
    public void ReadOnlyProof_RejectsUnregisteredProvider(string host,string database,string user,bool valid)
    {
        var builder = new Npgsql.NpgsqlConnectionStringBuilder { Host=host, Database=database, Username=user };
        Assert.Equal(valid, PortalClientCommand.IsRegisteredProofProvider(builder));
    }

    [Fact]
    public async Task ReadOnlyProof_InputIsBoundedAndRejectsEmptyOrOversize()
    {
        var bytes=System.Text.Encoding.UTF8.GetBytes("{\"clientId\":\"example\"}");
        Assert.Equal(bytes,await PortalClientCommand.ReadProofInputAsync(new MemoryStream(bytes)));
        await Assert.ThrowsAsync<PortalClientClosedException>(()=>PortalClientCommand.ReadProofInputAsync(new MemoryStream()));
        await Assert.ThrowsAsync<PortalClientClosedException>(()=>PortalClientCommand.ReadProofInputAsync(new MemoryStream(new byte[32769])));
    }

    [Theory]
    [InlineData(1654u,1654u,true,true)]
    [InlineData(1003u,1003u,false,true)]
    [InlineData(1003u,1003u,true,false)]
    [InlineData(1654u,1654u,false,false)]
    [InlineData(0u,0u,true,false)]
    public void VerifyUsesExistingAppPrincipalWithoutChangingRegistrationPrincipal(uint uid,uint gid,bool verify,bool valid)
        => Assert.Equal(valid,PortalClientCommand.IsAllowedPrincipal(uid,gid,verify));

    [Theory]
    [InlineData("https://t0000-auth.s001.pandalabs.cn/",true)]
    [InlineData("https://t0000-auth.s001.pandalabs.cn",true)]
    [InlineData("https://t0000-auth.s001.pandalabs.cn/other",false)]
    [InlineData("https://other.invalid/",false)]
    public void ReadOnlyProof_AcceptsOnlyTheTwoRegisteredIssuerForms(string issuer,bool valid)
        => Assert.Equal(valid,PortalClientCommand.IsRegisteredProofIssuer(issuer));

    [Fact]
    public void NormalHostBootstrap_OnlyKnownActualHostingPairsAreAccepted()
    {
        Assert.Equal(0, PortalClientCommand.Mode(["--environment=Development", "--applicationName=PandaAuth.Server"]));
        Assert.Equal(0, PortalClientCommand.Mode(["--environment=Production"]));
        Assert.Equal(0, PortalClientCommand.Mode(["--contentRoot=" + Directory.GetCurrentDirectory()]));
        Assert.Equal(-1, PortalClientCommand.Mode(["--contentRoot=relative-root"]));
    }

    [Theory]
    [InlineData("--environment=Development", "--environment=Production")]
    [InlineData("--environment=Production", "--register-portal-client")]
    [InlineData("--applicationName=other", "--environment=Production")]
    [InlineData("--urls=http://any.invalid", "--environment=Production")]
    [InlineData("--ConnectionStrings:Default=arbitrary", "--environment=Production")]
    public void NormalHostBootstrap_UnknownDuplicateAndMixedModesAreClosed(string first, string second)
        => Assert.Equal(-1, PortalClientCommand.Mode([first, second]));

    [Theory]
    [InlineData("--register-portal-client --migrate")]
    [InlineData("--register-portal-client --unregister-portal-client")]
    [InlineData("--register-portal-client --client-id arbitrary")]
    public async Task ActualProcess_RejectsModesBeforeProviderOrKeys(string args)
    {
        var executable = Path.GetFullPath("../../../../../src/PandaAuth.Server/bin/Debug/net10.0/PandaAuth.Server.dll", AppContext.BaseDirectory);
        var start = new ProcessStartInfo("dotnet", executable + " " + args) { RedirectStandardOutput = true, RedirectStandardError = true };
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        start.Environment["ConnectionStrings__Default"] = "Host=127.0.0.1;Port=1;Database=unreachable;Username=fixture;Password=fixture;Timeout=1";
        using var process = Process.Start(start)!;
        var stderr = await process.StandardError.ReadToEndAsync();
        var stdout = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        Assert.NotEqual(0, process.ExitCode);
        Assert.Equal("portal-client-command-closed\n", stderr.Replace("\r\n", "\n", StringComparison.Ordinal));
        Assert.Empty(stdout);
    }
}
