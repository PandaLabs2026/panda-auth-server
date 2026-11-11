using System.Diagnostics;
using System.Text.Json;
using PandaAuth.Server.Features.Profile;
using Xunit;

namespace PandaAuth.Tests;

public sealed class AvatarLinuxFactAttribute : FactAttribute
{
    public AvatarLinuxFactAttribute()
    { if (!OperatingSystem.IsLinux() || !File.Exists("/usr/bin/sleep")) Skip = "Requires Linux native sleep for disposable process cancellation proof."; }
}

public sealed class ProfileAvatarProcessTests
{
    [Fact]
    public void Decoder_worker_requires_only_Core_runtime_and_no_web_or_database_dependencies()
    {
        var executable = typeof(ProfileAvatarWorker).Assembly.Location;
        using var runtime = JsonDocument.Parse(File.ReadAllText(Path.ChangeExtension(executable, ".runtimeconfig.json")));
        var options = runtime.RootElement.GetProperty("runtimeOptions");
        var frameworks = options.TryGetProperty("frameworks", out var multiple)
            ? multiple.EnumerateArray().Select(value => value.GetProperty("name").GetString()!).ToArray()
            : [options.GetProperty("framework").GetProperty("name").GetString()!];
        Assert.Equal(new[] { "Microsoft.NETCore.App" }, frameworks);
        using var dependencies = JsonDocument.Parse(File.ReadAllText(Path.ChangeExtension(executable, ".deps.json")));
        Assert.DoesNotContain(dependencies.RootElement.GetProperty("libraries").EnumerateObject(), library =>
            library.Name.StartsWith("Microsoft.AspNetCore.", StringComparison.Ordinal)
            || library.Name.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal)
            || library.Name.StartsWith("PandaAuth.Server/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Real_worker_process_returns_normalized_png()
    {
        using var decoder = new ProfileAvatarDecoder();
        var result = await decoder.DecodeAsync(ct => File.ReadAllBytesAsync(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", "seed.jpg"), ct), default);
        Assert.True(result.AsSpan().StartsWith(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }));
    }

    [Fact]
    public async Task Real_worker_rejects_malformed_input_and_releases_capacity_for_next_decode()
    {
        using var decoder = new ProfileAvatarDecoder();
        var rejected = await Assert.ThrowsAsync<ProfileOperationException>(() =>
            decoder.DecodeAsync(_ => Task.FromResult(new byte[] { 1, 2, 3, 4 }), default));
        Assert.Equal(422, rejected.StatusCode);
        var recovered = await decoder.DecodeAsync(ct => File.ReadAllBytesAsync(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", "seed.png"), ct), default);
        Assert.NotEmpty(recovered);
    }

    [AvatarLinuxFact]
    public async Task Cancellation_kills_and_reaps_the_actual_process_before_returning()
    {
        using var process = new Process { StartInfo = new ProcessStartInfo("/usr/bin/sleep")
            { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false } };
        process.StartInfo.ArgumentList.Add("30");
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ProfileAvatarDecoder.RunProcessAsync(process, [], cancel.Token));
        Assert.True(process.HasExited);
    }

    [Fact]
    public async Task Admission_is_bounded_and_canceled_uploads_release_capacity()
    {
        using var decoder = new ProfileAvatarDecoder();
        using var cancel = new CancellationTokenSource();
        var entered = 0; var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<byte[]> Read(CancellationToken ct)
        {
            if (Interlocked.Increment(ref entered) == 3) ready.SetResult();
            await Task.Delay(Timeout.Infinite, ct); return [];
        }
        var tasks = Enumerable.Range(0, 3).Select(_ => decoder.DecodeAsync(Read, cancel.Token)).ToArray();
        await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var full = await Assert.ThrowsAsync<ProfileOperationException>(() => decoder.DecodeAsync(_ => Task.FromResult(Array.Empty<byte>()), default));
        Assert.Equal(429, full.StatusCode);
        cancel.Cancel();
        foreach (var task in tasks) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.Equal(3, entered);
        var result = await decoder.DecodeAsync(ct => File.ReadAllBytesAsync(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "ProfileAvatar", "seed.png"), ct), default);
        Assert.NotEmpty(result);
    }
}
