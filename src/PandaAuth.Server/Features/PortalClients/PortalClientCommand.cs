using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using static PandaAuth.Server.Features.PortalClients.PortalClientRequest;

namespace PandaAuth.Server.Features.PortalClients;

internal static class PortalClientCommand
{
    internal const string InputRoot = "/etc/panda-auth/t0000-portal";
    internal static int Mode(string[] args)
    {
        if (args.Length == 0) return 0;
        if (args.Length == 1)
        {
            if (args[0] == "--migrate") return 0;
            if (args[0] == "--register-portal-client") return 1;
            if (args[0] == "--unregister-portal-client") return 2;
        }
        // DeferredHostBuilder passes standard host settings to the normal entry point.
        // Dedicated commands remain single-argument; arbitrary configuration/URL pairs are closed.
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var arg in args)
        {
            var pair = arg.Split('=', 2);
            if (pair.Length != 2 || !keys.Add(pair[0])) return -1;
            if (pair[0] == "--environment" && pair[1] is "Production" or "Development" or "Staging") continue;
            if (pair[0] == "--applicationName" && pair[1] == "PandaAuth.Server") continue;
            if (pair[0] == "--contentRoot" && Path.IsPathFullyQualified(pair[1]) && Directory.Exists(pair[1])) continue;
            return -1;
        }
        return 0;
    }

    internal static async Task<int> RunAsync(bool unregister, IConfiguration configuration, TextWriter output, TextWriter error)
    {
        string? operation = null;
        try
        {
            Require(OperatingSystem.IsLinux() && Native.geteuid() == 1003 && Native.getegid() == 1003, "wrong-command-principal");
            var raw = ReadProtectedFile(InputRoot + (unregister ? "/registration-rollback.json" : "/registration-request.json"), 1003, true);
            operation = Parse(raw, unregister, DateTimeOffset.UtcNow).OperationId;
            var machine = ClosedJson(ReadProtectedFile(InputRoot + "/machine.json", 1003, false));
            Require(machine.TryGetProperty("machine_id", out var id) && id.GetString() == "tcloud-sh-01", "wrong-command-machine");
            Require(configuration["Auth:Issuer"] == Issuer, "wrong-runtime-issuer");
            var connection = configuration.GetConnectionString("Default") ?? throw new PortalClientClosedException("missing-runtime-provider");
            var parsed = new NpgsqlConnectionStringBuilder(connection);
            Require(!string.IsNullOrWhiteSpace(parsed.Host) && !string.IsNullOrWhiteSpace(parsed.Database) && !string.IsNullOrWhiteSpace(parsed.Username), "invalid-runtime-provider");
            using var services = Services(connection);
            var service = new PortalClientRegistrationService(services.GetRequiredService<IServiceScopeFactory>(), TimeProvider.System);
            await output.WriteAsync(await service.ExecuteAsync(raw, unregister));
            return 0;
        }
        catch (Exception failure)
        {
            var retryable = failure is PortalClientClosedException { Message: "retryable-operation-uncertain" };
            await error.WriteLineAsync((retryable ? "portal-client-command-retryable" : "portal-client-command-closed") +
                (operation is null ? "" : " operationId=" + operation));
            return retryable ? 2 : 1;
        }
    }
    internal static ServiceProvider Services(string connection)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.ClearProviders());
        services.AddDbContext<PandaAuthDbContext>(o => o.UseNpgsql(connection).UseOpenIddict());
        services.AddOpenIddict().AddCore(o => { o.DisableEntityCaching(); o.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>(); });
        services.AddScoped<AdminAuditWriter>();
        return services.BuildServiceProvider();
    }
    internal static byte[] ReadProtectedFile(string path, uint owner, bool request)
    {
        Require(OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64, "unsupported-command-platform");
        var file = new FileInfo(path);
        foreach (var parent in EnumerateParents(file.Directory))
        {
            var info = Native.Info(parent.FullName);
            Require(parent.LinkTarget is null && (info.Owner == 0 || info.Owner == owner) && (info.Mode & 0x12) == 0, "unsafe-input-parent");
        }
        var directory = Native.Info(file.DirectoryName!);
        Require(directory.Owner == owner && (directory.Mode & 0x1ff) == 0x1c0, "unsafe-input-directory"); //0700
        var before = Native.Info(path);
        Require(file.LinkTarget is null && before.Owner == owner && before.Links == 1 && (before.Mode & 0xf000) == 0x8000 &&
            (request ? (before.Mode & 0x1ff) == 0x100 : (before.Mode & 0x12) == 0), "unsafe-input-file"); //0400 request; public machine marker permits0644
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actual = Native.Info(stream.SafeFileHandle.DangerousGetHandle().ToInt32());
        Require(actual.Device == before.Device && actual.Inode == before.Inode && actual.Owner == before.Owner && actual.Mode == before.Mode && actual.Links == 1 && stream.Length is > 0 and <= 32768, "input-race");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
        var after = Native.Info(path);
        Require(after.Device == actual.Device && after.Inode == actual.Inode && after.Mode == actual.Mode && after.Owner == actual.Owner && after.Links == 1, "input-race");
        return bytes;
    }
    private static IEnumerable<DirectoryInfo> EnumerateParents(DirectoryInfo? directory)
    { while (directory is not null) { yield return directory; directory = directory.Parent; } }
    internal static class Native
    {
        [DllImport("libc", SetLastError = true)] internal static extern uint geteuid();
        [DllImport("libc", SetLastError = true)] internal static extern uint getegid();
        [DllImport("libc", SetLastError = true)] private static extern int lstat(string path, byte[] buffer);
        [DllImport("libc", SetLastError = true)] private static extern int fstat(int fd, byte[] buffer);
        internal readonly record struct Metadata(ulong Device, ulong Inode, ulong Links, uint Mode, uint Owner);
        private static Metadata Decode(byte[] raw) => new(BitConverter.ToUInt64(raw, 0), BitConverter.ToUInt64(raw, 8), BitConverter.ToUInt64(raw, 16), BitConverter.ToUInt32(raw, 24), BitConverter.ToUInt32(raw, 28));
        internal static Metadata Info(string path) { var bytes = new byte[256]; Require(lstat(path, bytes) == 0, "missing-input"); return Decode(bytes); }
        internal static Metadata Info(int fd) { var bytes = new byte[256]; Require(fstat(fd, bytes) == 0, "missing-input"); return Decode(bytes); }
    }
}
