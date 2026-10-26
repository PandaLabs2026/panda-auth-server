using System.Text.Json;
using System.Diagnostics;

namespace PandaAuth.ReadinessHarness;

public static class HarnessProgram
{
    public static object DescribeFailure(Exception exception) => new
    {
        schema = 1, valid = false, error = "readiness_harness_failed", kind = exception.GetType().Name,
        protocol = exception is SnapshotProtocolException protocol ? new { cookieStatus = protocol.CookieStatus,
            bearerStatus = protocol.BearerStatus, refreshStatus = protocol.RefreshStatus,
            loginRedirect = protocol.LoginRedirect, refreshError = protocol.RefreshError,
            redirectOwnerMatches = protocol.RedirectOwnerMatches, redirectScheme = protocol.RedirectScheme,
            redirectPath = protocol.RedirectPath } : null,
        stack = (new StackTrace(exception, true).GetFrames() ?? []).Where(frame =>
            frame.GetMethod()?.DeclaringType?.Assembly == typeof(HarnessProgram).Assembly).Take(6)
            .Select(frame => new { type = frame.GetMethod()?.DeclaringType?.FullName,
                method = frame.GetMethod()?.Name, line = frame.GetFileLineNumber() }).ToArray()
    };
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["--controlled-crypto-baseline-stdin" or "--controlled-crypto-verify-stdin"])
                return await ControlledCryptoCommand.Dispatch(args[0], await Console.In.ReadLineAsync() ?? "");
            if (args is ["--controlled-proxy-stdin" or "--controlled-probe-stdin" or "--controlled-transport-smoke-stdin"])
                return await ControlledTransport.Dispatch(args[0], await Console.In.ReadLineAsync() ?? "");
            if (args is not ["--load-stdin" or "--seed-stdin" or "--proxy-stdin" or "--create-tls-stdin" or "--probe-stdin" or "--verify-ip-limit-stdin" or "--verify-account-limit-stdin" or "--create-recovery-crypto-stdin" or "--verify-recovery-crypto-stdin" or "--snapshot-session-stdin" or "--snapshot-revoked-session-stdin" or "--verify-valid-snapshot-stdin" or "--verify-rejected-snapshot-stdin" or "--verify-bff-login-stdin" or "--snapshot-bff-login-stdin" or "--verify-bff-snapshot-stdin" or "--verify-legacy-bff-snapshot-stdin"]) throw new InvalidOperationException();
            var line = await Console.In.ReadLineAsync();
            if (args[0] is "--create-recovery-crypto-stdin" or "--verify-recovery-crypto-stdin")
            {
                var cryptoInput = JsonSerializer.Deserialize<RecoveryCryptoInput>(line ?? "", Json) ?? throw new InvalidOperationException();
                var key = Convert.FromBase64String(cryptoInput.TotpKey);
                if (args[0] == "--create-recovery-crypto-stdin") RecoveryCrypto.Create(cryptoInput.Directory, cryptoInput.RunId, key, cryptoInput.UseExistingKeyrings);
                else RecoveryCrypto.Verify(cryptoInput.Directory, cryptoInput.RunId, key);
                Console.WriteLine(JsonSerializer.Serialize(new { schema = 1, valid = true, cryptoInput.RunId }, Json));
                return 0;
            }
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
            if (args[0] is "--snapshot-bff-login-stdin" or "--verify-bff-snapshot-stdin" or "--verify-legacy-bff-snapshot-stdin")
            {
                var report = args[0] == "--snapshot-bff-login-stdin" ? await BffCookieSnapshot.CreateAsync(input)
                    : await BffCookieSnapshot.VerifyAsync(input, args[0] == "--verify-legacy-bff-snapshot-stdin");
                Console.WriteLine(JsonSerializer.Serialize(report, Json));
                return 0;
            }
            if (args[0] == "--verify-bff-login-stdin")
            {
                input.Validate();
                using var certificate = ProtocolSnapshot.Certificate(input);
                using var browser = ProtocolUser.CreateBrowser(input, certificate);
                Console.WriteLine(JsonSerializer.Serialize(await BffLogin.VerifyAsync(input, browser), Json));
                return 0;
            }
            if (args[0] is "--snapshot-session-stdin" or "--snapshot-revoked-session-stdin" or "--verify-valid-snapshot-stdin" or "--verify-rejected-snapshot-stdin")
            {
                var report = args[0].StartsWith("--snapshot-", StringComparison.Ordinal)
                    ? await ProtocolSnapshot.CreateAsync(input, args[0] == "--snapshot-revoked-session-stdin")
                    : await ProtocolSnapshot.VerifyAsync(input, args[0] == "--verify-rejected-snapshot-stdin");
                Console.WriteLine(JsonSerializer.Serialize(report, Json));
                return 0;
            }
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
                using var response = await browser.GetAsync(input.ProbePath);
                Console.WriteLine(JsonSerializer.Serialize(new { schema = 1, valid = response.IsSuccessStatusCode, status = (int)response.StatusCode }, Json));
                return response.IsSuccessStatusCode ? 0 : 2;
            }
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, interrupted) => { interrupted.Cancel = true; cancellation.Cancel(); };
            var result = args[0] == "--seed-stdin" ? await FixtureSeed.RunAsync(input) : await LoadRunner.RunAsync(input, Console.Out, cancellation.Token);
            Console.WriteLine(JsonSerializer.Serialize(result, Json));
            return 0;
        }
        catch (Exception exception)
        {
            Console.WriteLine(JsonSerializer.Serialize(DescribeFailure(exception), Json));
            return 2;
        }
    }
}
