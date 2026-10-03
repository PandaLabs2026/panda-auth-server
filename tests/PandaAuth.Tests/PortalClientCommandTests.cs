using System.Diagnostics;
using PandaAuth.Server.Features.PortalClients;
using Xunit;

namespace PandaAuth.Tests;

public class PortalClientCommandTests
{
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
