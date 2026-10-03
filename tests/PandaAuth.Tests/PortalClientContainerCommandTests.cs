using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Features.PortalClients;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public class PortalClientContainerCommandTests
{
    // Task verification runtime: pinned ASP.NET10.0.12 with the existing Auth image's curl dependency.
    // Actual task-published Auth DLL is mounted and selected explicitly, without production files.
    internal const string Runtime = "sha256:afdb2da8488c675f9b9d786a6a0b01588fd8f9d1130f99b4bff37debe2898630";
    private const string Published = "/tmp/panda-fleet-lifecycle-20261003/tooling/t0a2-publish";

    [PostgresFact]
    public async Task ActualProductProcess_UID1003_FixedProtectedMount_RegisterRecoverUnregister_NoKeysSeedOrListener()
    {
        await using var fixture = await RegistrationDatabase.CreateAsync();
        var root = Directory.CreateTempSubdirectory("panda-auth-t0a2-command-").FullName;
        var inputs = Path.Combine(root, "inputs"); Directory.CreateDirectory(inputs);
        var environment = Path.Combine(root, "command.env");
        var raw = PortalClientRegistrationPostgresTests.Request();
        var request = Path.Combine(inputs, "registration-request.json");
        var rollback = Path.Combine(inputs, "registration-rollback.json");
        await File.WriteAllBytesAsync(request, raw); await File.WriteAllTextAsync(rollback, "{}");
        await File.WriteAllTextAsync(Path.Combine(inputs, "machine.json"), "{\"machine_id\":\"tcloud-sh-01\"}");
        await File.WriteAllLinesAsync(environment, ["ASPNETCORE_ENVIRONMENT=Production", "Auth__Issuer=" + PortalClientRequest.Issuer,
            "ConnectionStrings__Default=" + fixture.Connection, "Auth__Seed__Enabled=true", "Auth__DataProtectionKeyPath=/must-not-create-t0a2-keys"]);
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Requires task Linux container.");
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.SetUnixFileMode(environment, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        try
        {
            await OwnershipAsync(inputs, 1003, true);
            var wrongPrincipal = await RunAsync(inputs, environment, "--register-portal-client", "1000:1000");
            Assert.Equal(1, wrongPrincipal.ExitCode); Assert.Empty(wrongPrincipal.Output); Assert.Equal("portal-client-command-closed\n", wrongPrincipal.Error);
            await OwnershipAsync(inputs, 1003, true, writableRequest: true);
            var unsafeInput = await RunAsync(inputs, environment, "--register-portal-client");
            Assert.Equal(1, unsafeInput.ExitCode); Assert.Empty(unsafeInput.Output); Assert.Equal("portal-client-command-closed\n", unsafeInput.Error);
            await OwnershipAsync(inputs, 1003, true);
            Assert.Equal((0, 0), await fixture.CountsAsync());
            var first = await RunAsync(inputs, environment, "--register-portal-client");
            Assert.Equal(0, first.ExitCode); Assert.Empty(first.Error);
            var original = first.Output;
            using var receipt = JsonDocument.Parse(original);
            Assert.Equal("created", receipt.RootElement.GetProperty("result").GetString());
            var recovered = await RunAsync(inputs, environment, "--register-portal-client");
            Assert.Equal(0, recovered.ExitCode); Assert.Equal(original, recovered.Output); Assert.Empty(recovered.Error);
            await using (var scope = fixture.Provider.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<PandaAuthDbContext>();
                Assert.Equal(0, await db.SigningKeys.CountAsync()); Assert.Equal(0, await db.Users.CountAsync()); Assert.Equal(0, await db.Roles.CountAsync());
                Assert.Equal((1, 1), await fixture.CountsAsync());
            }
            await PortalClientLogoutProtocolTests.VerifyRegisteredPublicLogoutAsync(fixture, original);
            await OwnershipAsync(inputs, PortalClientCommand.Native.geteuid(), false);
            await File.WriteAllBytesAsync(rollback, PortalClientRegistrationPostgresTests.Rollback(original));
            await OwnershipAsync(inputs, 1003, true);
            var removed = await RunAsync(inputs, environment, "--unregister-portal-client");
            Assert.Equal(0, removed.ExitCode); Assert.Empty(removed.Error);
            var repeated = await RunAsync(inputs, environment, "--unregister-portal-client");
            Assert.Equal(0, repeated.ExitCode); Assert.Equal(removed.Output, repeated.Output); Assert.Empty(repeated.Error);
            var terminal = await RunAsync(inputs, environment, "--register-portal-client");
            Assert.Equal(1, terminal.ExitCode); Assert.Empty(terminal.Output); Assert.StartsWith("portal-client-command-closed operationId=", terminal.Error);
            Assert.Equal((0, 2), await fixture.CountsAsync());
            var remaining = await DockerAsync(["ps", "-aq", "--filter", "label=panda.task=t0a2-command"]);
            Assert.Equal(0, remaining.ExitCode); Assert.Empty(remaining.Output);
        }
        finally
        {
            await OwnershipAsync(inputs, PortalClientCommand.Native.geteuid(), false);
            Directory.Delete(root, true);
        }
    }
    private static async Task OwnershipAsync(string inputs, uint owner, bool operatorFiles, bool writableRequest = false)
    {
        var name = "panda-auth-t0a2-permissions-" + Guid.NewGuid().ToString("N");
        var permission = operatorFiles ? "chmod 700 /input; chmod 400 /input/registration-request.json /input/registration-rollback.json; chmod 644 /input/machine.json" : "chmod 700 /input; chmod 600 /input/registration-request.json /input/registration-rollback.json /input/machine.json";
        if (writableRequest) permission += "; chmod 600 /input/registration-request.json";
        var result = await DockerAsync(["run", "--rm", "--name", name, "--label", "panda.task=t0a2-command", "--network", "none", "--read-only", "--user", "0:0",
            "--mount", "type=bind,source=" + inputs + ",target=/input", "--entrypoint", "/bin/sh", Runtime, "-c", "chown " + owner + ":" + owner + " /input /input/registration-request.json /input/registration-rollback.json /input/machine.json; " + permission]);
        Assert.True(result.ExitCode == 0, "Task input ownership helper failed.");
    }
    private static Task<CommandResult> RunAsync(string inputs, string environment, string mode, string user = "1003:1003")
        => DockerAsync(["run", "--rm", "--name", "panda-auth-t0a2-command-" + Guid.NewGuid().ToString("N"), "--label", "panda.task=t0a2-command", "--network", "host",
            "--read-only", "--user", user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--env-file", environment,
            "--mount", "type=bind,source=" + inputs + ",target=/etc/panda-auth/t0000-portal,readonly",
            "--mount", "type=bind,source=" + Published + ",target=/task/auth,readonly", "--workdir", "/task/auth", "--entrypoint", "dotnet", Runtime, "PandaAuth.Server.dll", mode]);
    private static async Task<CommandResult> DockerAsync(string[] args)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));
        return new(process.ExitCode, await output, await error);
    }
    private sealed record CommandResult(int ExitCode, string Output, string Error);
}
