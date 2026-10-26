using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using PandaAuth.Server.Infrastructure.Security.Mfa;

namespace PandaAuth.ReadinessHarness;

public sealed record RecoveryCryptoInput(string Directory, string RunId, string TotpKey, bool UseExistingKeyrings = false);
public sealed class RecoveryKeyringMissingException() : InvalidOperationException("recovery_keyring_missing");

public static class RecoveryCrypto
{
    internal static readonly System.Collections.ObjectModel.ReadOnlyDictionary<string, string> Applications = new(new Dictionary<string, string>()
    {
        ["server"] = "PandaAuth", ["admin"] = "PandaAuth.Admin", ["me"] = "PandaAuth.Me"
    });
    private sealed record Canary(string RunId, Dictionary<string, string> Dp, Guid FactorId, ProtectedTotpSecret Totp);

    public static void Create(string root, string runId, byte[] totpKey, bool useExistingKeyrings = false)
    {
        Admit(root, runId, totpKey);
        var protectedValues = new Dictionary<string, string>();
        foreach (var (component, application) in Applications)
        {
            var directory = Path.Combine(root, component);
            if (useExistingKeyrings) RequireExistingKeyring(directory);
            else
            {
                if (Directory.Exists(directory)) throw new InvalidOperationException("recovery_keyring_already_exists");
                Directory.CreateDirectory(directory);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            var provider = DataProtectionProvider.Create(new DirectoryInfo(directory), builder =>
            {
                builder.SetApplicationName(application);
                if (useExistingKeyrings) builder.DisableAutomaticKeyGeneration();
            });
            protectedValues[component] = provider.CreateProtector("PandaAuth.R1.RecoveryCanary").Protect(Value(runId, component));
        }
        var factor = Guid.NewGuid();
        var protector = new TotpSecretProtector(totpKey, "r1-fixture-v1");
        var canary = new Canary(runId, protectedValues, factor, protector.Protect("r1-" + runId, factor, SyntheticTotpSecret(runId)));
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var output = new FileStream(Path.Combine(root, "crypto-canary.json"), options);
        JsonSerializer.Serialize(output, canary);
    }

    public static bool Verify(string root, string runId, byte[] totpKey)
    {
        Admit(root, runId, totpKey);
        var path = Path.Combine(root, "crypto-canary.json");
        if (!File.Exists(path) || new FileInfo(path).Length > 16384 || File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException("recovery_canary_invalid");
        var canary = JsonSerializer.Deserialize<Canary>(File.ReadAllText(path)) ?? throw new InvalidOperationException("recovery_canary_invalid");
        if (canary.RunId != runId || canary.Dp is null || !canary.Dp.Keys.Order().SequenceEqual(Applications.Keys.Order()))
            throw new InvalidOperationException("recovery_canary_binding_invalid");
        foreach (var (component, application) in Applications)
        {
            var directory = Path.Combine(root, component);
            RequireExistingKeyring(directory);
            var provider = DataProtectionProvider.Create(new DirectoryInfo(directory), builder =>
            {
                builder.SetApplicationName(application);
                builder.DisableAutomaticKeyGeneration();
            });
            if (provider.CreateProtector("PandaAuth.R1.RecoveryCanary").Unprotect(canary.Dp[component]) != Value(runId, component))
                throw new CryptographicException("recovery_dp_invalid");
        }
        var secret = new TotpSecretProtector(totpKey, "r1-fixture-v1").Unprotect("r1-" + runId, canary.FactorId, canary.Totp);
        if (!CryptographicOperations.FixedTimeEquals(secret, SyntheticTotpSecret(runId))) throw new CryptographicException("recovery_totp_invalid");
        return true;
    }

    private static string Value(string runId, string component) => "panda-auth-r1-crypto-" + runId + "-" + component;
    internal static byte[] SyntheticTotpSecret(string runId) => SHA256.HashData(Encoding.UTF8.GetBytes("synthetic-totp-" + runId))[..20];

    private static void RequireExistingKeyring(string directory)
    {
        if (!Directory.Exists(directory))
            throw new RecoveryKeyringMissingException();
        if (File.GetAttributes(directory).HasFlag(FileAttributes.ReparsePoint) ||
            Directory.GetFiles(directory).Any(key => File.GetAttributes(key).HasFlag(FileAttributes.ReparsePoint)))
            throw new InvalidOperationException("recovery_keyring_link_invalid");
        if (Directory.GetFiles(directory, "*.xml").Length == 0) throw new RecoveryKeyringMissingException();
    }

    private static void Admit(string root, string runId, byte[] totpKey)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(root));
        if (!Regex.IsMatch(runId, "\\A[a-f0-9]{32}\\z") || directory.Name != "panda-r1-recovery-" + runId ||
            !directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint) || totpKey.Length != 32)
            throw new InvalidOperationException("recovery_fixture_boundary_invalid");
        // Only this task's organization temp tree or its nonce-bound Docker fixture is admitted.
        var temporary = Path.GetFullPath(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath());
        var relative = Path.GetRelativePath(temporary, directory.FullName);
        var inTemporary = relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar) && !Path.IsPathRooted(relative);
        var isolated = OperatingSystem.IsLinux() && File.Exists("/.dockerenv") && directory.Parent?.FullName == "/fixture" &&
            Environment.GetEnvironmentVariable("PANDA_AUTH_R1_ISOLATED_RUN") == runId;
        if (!inTemporary && !isolated) throw new InvalidOperationException("recovery_fixture_boundary_invalid");
    }
}
