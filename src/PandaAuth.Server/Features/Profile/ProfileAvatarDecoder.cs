using System.ComponentModel;
using System.Buffers.Binary;
using System.Diagnostics;

namespace PandaAuth.Server.Features.Profile;

/// <summary>One native worker plus two bounded upload buffers. No native work runs in the web process.</summary>
public sealed class ProfileAvatarDecoder : IDisposable
{
    private readonly SemaphoreSlim admission = new(3, 3);
    private readonly SemaphoreSlim worker = new(1, 1);

    public async Task<byte[]> DecodeAsync(Func<CancellationToken, Task<byte[]>> read, CancellationToken ct)
    {
        if (!await admission.WaitAsync(0, ct)) throw new ProfileOperationException("profile_rate_limited", 429);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            var bytes = await read(deadline.Token);
            if (bytes.Length is < 1 or > 2097152) throw new ProfileOperationException("profile_avatar_invalid", 422);
            await worker.WaitAsync(deadline.Token);
            try
            {
                using var process = new Process { StartInfo = WorkerStart() };
                return await RunProcessAsync(process, bytes, deadline.Token);
            }
            finally { worker.Release(); }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw new ProfileOperationException("profile_avatar_unavailable", 503); }
        finally { admission.Release(); }
    }

    private static ProcessStartInfo WorkerStart()
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Process executable unavailable.");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = AppContext.BaseDirectory,
        };
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(ProfileAvatarWorker).Assembly.Location);
        start.ArgumentList.Add("--profile-avatar-decode");
        // Do not inherit database, mail, signing, or other web-process secrets.
        start.Environment.Clear();
        foreach (var name in new[] { "DOTNET_ROOT", "DOTNET_ROOT_X64", "TMPDIR", "TMP", "TEMP", "SystemRoot" })
            if (Environment.GetEnvironmentVariable(name) is { } value) start.Environment[name] = value;
        start.Environment["DOTNET_PROCESSOR_COUNT"] = "1";
        start.Environment["DOTNET_GCHeapHardLimit"] = "4000000"; // 64 MiB managed heap; native policy separately caps its pixel cache.
        return start;
    }

    internal static async Task<byte[]> RunProcessAsync(Process process, byte[] bytes, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var started = false;
        try
        {
            process.Start(); started = true;
            async Task Write()
            {
                await process.StandardInput.BaseStream.WriteAsync(bytes, ct);
                process.StandardInput.Close();
            }
            async Task<byte[]> Read()
            {
                using var output = new MemoryStream();
                var buffer = new byte[8192];
                while (true)
                {
                    var count = await process.StandardOutput.BaseStream.ReadAsync(buffer, ct);
                    if (count == 0) break;
                    if (output.Length + count > 262144) throw new ProfileOperationException("profile_avatar_invalid", 422);
                    output.Write(buffer, 0, count);
                }
                return output.ToArray();
            }
            async Task DiscardErrors()
            {
                var buffer = new byte[4096];
                while (await process.StandardError.BaseStream.ReadAsync(buffer, ct) != 0) { }
            }
            var output = Read();
            await Task.WhenAll(Write(), output, DiscardErrors(), process.WaitForExitAsync(ct));
            if (process.ExitCode == 65) throw new ProfileOperationException("profile_avatar_invalid", 422);
            var png = output.Result;
            if (process.ExitCode != 0 || png.Length < 24
                || !png.AsSpan().StartsWith(new byte[] {137,80,78,71,13,10,26,10})
                || BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(16, 4)) is < 1 or > 512
                || BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(20, 4)) is < 1 or > 512)
                throw new ProfileOperationException("profile_avatar_unavailable", 503);
            return png;
        }
        catch (IOException) { throw new ProfileOperationException("profile_avatar_invalid", 422); }
        catch (Win32Exception) { throw new ProfileOperationException("profile_avatar_unavailable", 503); }
        finally
        {
            if (started)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                finally
                {
                    // Even if termination reports an error, retain capacity until the process is reaped.
                    await process.WaitForExitAsync(CancellationToken.None);
                }
            }
        }
    }

    public void Dispose() { worker.Dispose(); admission.Dispose(); }
}
