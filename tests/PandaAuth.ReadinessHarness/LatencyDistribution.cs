namespace PandaAuth.ReadinessHarness;

public sealed record LatencySummary(long Count, double MeanMs, int P50Ms, int P95Ms, int P99Ms);

public sealed class LatencyDistribution
{
    private readonly long[] milliseconds = new long[60_002];
    private long microseconds;

    public void Record(double elapsedMilliseconds)
    {
        if (!double.IsFinite(elapsedMilliseconds) || elapsedMilliseconds < 0) throw new ArgumentOutOfRangeException(nameof(elapsedMilliseconds));
        Interlocked.Increment(ref milliseconds[(int)Math.Min(60_001, Math.Ceiling(elapsedMilliseconds))]);
        Interlocked.Add(ref microseconds, (long)(elapsedMilliseconds * 1000));
    }

    public LatencySummary Snapshot()
    {
        var buckets = milliseconds.Select(value => value).ToArray();
        var count = buckets.Sum();
        int Percentile(double percentile)
        {
            if (count == 0) return 0;
            var target = (long)Math.Ceiling(count * percentile);
            long sum = 0;
            for (var index = 0; index < buckets.Length; index++) if ((sum += buckets[index]) >= target) return index;
            return buckets.Length - 1;
        }
        return new(count, count == 0 ? 0 : Interlocked.Read(ref microseconds) / 1000d / count, Percentile(.5), Percentile(.95), Percentile(.99));
    }
}
