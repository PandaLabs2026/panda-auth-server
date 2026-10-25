using System.Text.Json;

namespace PandaAuth.ReadinessHarness;

public static class HarnessProgram
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is not ["--load-stdin" or "--seed-stdin" or "--proxy-stdin" or "--create-tls-stdin" or "--probe-stdin" or "--verify-ip-limit-stdin" or "--verify-account-limit-stdin"]) throw new InvalidOperationException();
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
            if (args[0] is "--verify-ip-limit-stdin" or "--verify-account-limit-stdin")
            {
                Console.WriteLine(JsonSerializer.Serialize(await DefaultLimitProbe.RunAsync(input, args[0] == "--verify-account-limit-stdin"), Json));
                return 0;
            }
            if (args[0] == "--probe-stdin")
            {
                input.Validate();
                using var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(input.RootCertificateFile);
                using var browser = ProtocolUser.CreateBrowser(input, certificate);
                using var response = await browser.GetAsync("/healthz");
                Console.WriteLine(JsonSerializer.Serialize(new { schema = 1, valid = response.IsSuccessStatusCode, status = (int)response.StatusCode }, Json));
                return response.IsSuccessStatusCode ? 0 : 2;
            }
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
