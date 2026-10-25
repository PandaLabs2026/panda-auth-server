using System.Text.Json;

namespace PandaAuth.ReadinessHarness;

public static class HarnessProgram
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is not ["--load-stdin" or "--seed-stdin" or "--proxy-stdin" or "--create-tls-stdin"]) throw new InvalidOperationException();
            var line = await Console.In.ReadLineAsync();
            if (args[0] == "--create-tls-stdin")
            {
                var certificate = JsonSerializer.Deserialize<CertificateRequestInput>(line ?? "", Json) ?? throw new InvalidOperationException();
                Console.WriteLine(JsonSerializer.Serialize(FixtureCertificate.Create(certificate), Json));
                return 0;
            }
            if (args[0] == "--proxy-stdin")
            {
                var proxy = JsonSerializer.Deserialize<ProxyRequest>(line ?? "", Json) ?? throw new InvalidOperationException();
                await FixtureProxy.RunAsync(proxy);
                return 0;
            }
            var input = JsonSerializer.Deserialize<LoadRequest>(line ?? "", Json) ?? throw new InvalidOperationException();
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, interrupted) => { interrupted.Cancel = true; cancellation.Cancel(); };
            var result = args[0] == "--seed-stdin" ? await FixtureSeed.RunAsync(input) : await LoadRunner.RunAsync(input, Console.Out, cancellation.Token);
            Console.WriteLine(JsonSerializer.Serialize(result, Json));
            return 0;
        }
        catch (Exception)
        {
            Console.WriteLine("{\"schema\":1,\"valid\":false,\"error\":\"readiness_harness_failed\"}");
            return 2;
        }
    }
}
