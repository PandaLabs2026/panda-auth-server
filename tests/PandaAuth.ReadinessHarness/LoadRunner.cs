using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using PandaAuth.Shared;

namespace PandaAuth.ReadinessHarness;

public static class LoadRunner
{
    public static async Task<object> RunAsync(LoadRequest settings, TextWriter output, CancellationToken cancellation)
    {
        settings.Validate();
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(settings.RootCertificateFile);
        if (certificate.GetNameInfo(X509NameType.SimpleName, false) != "panda-auth-r1-" + settings.RunId)
            throw new InvalidOperationException("readiness_fixture_certificate_mismatch");
        using (var browser = ProtocolUser.CreateBrowser(settings, certificate))
        {
            using var response = await browser.GetAsync(PandaAuthEndpoints.OpenIdConfiguration, cancellation);
            response.EnsureSuccessStatusCode();
            using var discovery = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellation));
            if (discovery.RootElement.GetProperty("issuer").GetString() != settings.BaseUri)
                throw new InvalidOperationException("readiness_fixture_issuer_mismatch");
        }
        var users = Enumerable.Range(0, settings.Concurrency).Select(index => new ProtocolUser(settings, index, certificate)).ToArray();
        try
        {
            await Task.WhenAll(users.Select(user => user.InitializeAsync(cancellation)));
            if (settings.WarmupSeconds > 0) await PhaseAsync(settings.WarmupSeconds);
            await output.WriteLineAsync(JsonSerializer.Serialize(new { kind = "measurement_started", workload = settings.Workload, concurrency = settings.Concurrency }));
            await output.FlushAsync(cancellation);
            var (latency, statuses, unexpected, stopped, elapsed) = await PhaseAsync(settings.DurationSeconds);
            var distribution = latency.Snapshot();
            return new
            {
                schema = 1, kind = "capacity_sample", settings.RunId, settings.Workload, settings.Concurrency,
                complete = !stopped && distribution.Count > 0, stopped, elapsedSeconds = elapsed,
                completed = statuses.Values.Sum(), successful = distribution.Count, unexpectedErrors = unexpected,
                throughput = distribution.Count / Math.Max(elapsed, .001), latency = distribution,
                statusCounts = statuses.OrderBy(pair => pair.Key).ToDictionary(pair => pair.Key, pair => pair.Value)
            };
        }
        finally { foreach (var user in users) user.Dispose(); }

        async Task<(LatencyDistribution Latency, ConcurrentDictionary<int, long> Statuses, long Unexpected, bool Stopped, double Elapsed)> PhaseAsync(int seconds)
        {
            var latency = new LatencyDistribution();
            var statuses = new ConcurrentDictionary<int, long>();
            long unexpected = 0;
            using var phase = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            phase.CancelAfter(TimeSpan.FromSeconds(seconds));
            var start = Stopwatch.GetTimestamp();
            var stopped = 0;
            await Task.WhenAll(users.Select(async user =>
            {
                while (!phase.IsCancellationRequested)
                {
                    if (settings.StopFile.Length > 0 && File.Exists(settings.StopFile))
                    { Interlocked.Exchange(ref stopped, 1); await phase.CancelAsync(); break; }
                    var request = Stopwatch.GetTimestamp();
                    try
                    {
                        var status = await user.StepAsync(phase.Token);
                        statuses.AddOrUpdate((int)status, 1, (_, count) => count + 1);
                        if (status == HttpStatusCode.OK) latency.Record(Stopwatch.GetElapsedTime(request).TotalMilliseconds);
                        else Interlocked.Increment(ref unexpected);
                    }
                    catch (OperationCanceledException) when (phase.IsCancellationRequested) { break; }
                    catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or JsonException or OperationCanceledException)
                    { statuses.AddOrUpdate(0, 1, (_, count) => count + 1); Interlocked.Increment(ref unexpected); }
                }
            }));
            return (latency, statuses, unexpected, stopped != 0 || cancellation.IsCancellationRequested, Stopwatch.GetElapsedTime(start).TotalSeconds);
        }
    }
}
