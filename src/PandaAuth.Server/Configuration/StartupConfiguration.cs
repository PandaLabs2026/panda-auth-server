using Microsoft.AspNetCore.HttpOverrides;
using Npgsql;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Server.Configuration;

public sealed record ConfigurationError(string Key, string Code);
public sealed record ConfigurationReport(int Schema, bool Valid, ConfigurationError[] Errors);

/// <summary>Side-effect-free apart from an immediately deleted, uniquely named DP permission probe.</summary>
public static class StartupConfiguration
{
    public static ConfigurationReport Validate(IConfiguration configuration, IHostEnvironment environment, bool migrate)
    {
        var errors = new List<ConfigurationError>();
        void Check(string key, string code, Action check)
        {
            try { check(); }
            catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or FormatException or
                IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { errors.Add(new(key, code)); }
        }
        AuthOptions? options = null;
        Check("Auth", "auth_binding_invalid", () => options = configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>() ?? new());
        var connectionKey = migrate ? "Migration" : "Default";
        Check("ConnectionStrings:" + connectionKey, "connection_invalid", () =>
        {
            var connection = new NpgsqlConnectionStringBuilder(configuration.GetConnectionString(connectionKey));
            if (string.IsNullOrWhiteSpace(connection.Host) || string.IsNullOrWhiteSpace(connection.Database) || string.IsNullOrWhiteSpace(connection.Username))
                throw new InvalidOperationException();
        });
        if (options is null) return new(1, false, errors.ToArray());
        var production = environment.IsProduction();
        Check("Auth:Issuer", "issuer_invalid", () =>
        {
            if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) || string.IsNullOrWhiteSpace(issuer.Host) ||
                issuer.UserInfo.Length > 0 || issuer.Query.Length > 0 || issuer.Fragment.Length > 0 ||
                (issuer.Scheme != Uri.UriSchemeHttps && (issuer.Scheme != Uri.UriSchemeHttp || !issuer.IsLoopback)))
                throw new InvalidOperationException();
        });
        if (production && Uri.TryCreate(options.Issuer, UriKind.Absolute, out var canonical) && canonical.Scheme != Uri.UriSchemeHttps)
            errors.Add(new("Auth:Issuer", "issuer_https_required"));
        Check("Auth:Keys", "signing_window_invalid", options.Keys.Validate);
        Check("Auth:Retention", "retention_invalid", options.Retention.Validate);
        Check("Auth:Mfa", "mfa_invalid", () => options.Mfa.Validate(production));
        Check("Auth:Seed:CloudConfig", "cloud_registration_invalid", () => CloudConfigRegistration.Validate(options));
        if (migrate)
        {
            if (options.Seed.Enabled) Check("Auth:Seed", "seed_permissions_invalid", () => SeedPermissionPolicy.Validate(options.Seed));
            return new(1, errors.Count == 0, errors.ToArray());
        }
        Check("PANDA_AUTH_TRUSTED_PROXY", "proxy_invalid", () => TenantForwardedHeaders.Configure(new ForwardedHeadersOptions(), configuration));
        if (production && options.CookieSecure != CookieSecurePolicy.Always)
            errors.Add(new("Auth:CookieSecure", "secure_cookie_required"));
        if (production && string.IsNullOrWhiteSpace(options.DataProtectionKeyPath))
            errors.Add(new("Auth:DataProtectionKeyPath", "dp_required"));
        else if (!string.IsNullOrWhiteSpace(options.DataProtectionKeyPath))
            Check("Auth:DataProtectionKeyPath", "dp_not_writable", () => ProbeDirectory(options.DataProtectionKeyPath));
        Check("Auth:RateLimit", "rate_limit_invalid", () =>
        {
            if (new[] { options.RateLimit.IpPerMinute, options.RateLimit.AccountPerMinute,
                options.RateLimit.MfaChallengeIpPerMinute, options.RateLimit.MfaChallengeAccountPerMinute,
                options.Mgmt.RateLimit.ReadPerMinute, options.Mgmt.RateLimit.WritePerMinute, options.Mgmt.RateLimit.SecretPerMinute,
                options.Audit.RetentionDays }.Any(value => value <= 0)) throw new InvalidOperationException();
        });
        Check("Email", "email_invalid", () =>
        {
            var email = configuration.GetSection(EmailOptions.SectionName).Get<EmailOptions>() ?? new();
            if (!EmailIsValid(email, production)) throw new InvalidOperationException();
        });
        return new(1, errors.Count == 0, errors.ToArray());
    }

    internal static bool EmailIsValid(EmailOptions options, bool production) => !production ||
        (options.Transport.Equals("Resend", StringComparison.OrdinalIgnoreCase)
            ? !string.IsNullOrWhiteSpace(options.ApiKey) && !string.IsNullOrWhiteSpace(options.FromAddress)
            : options.Transport.Equals("Notify", StringComparison.OrdinalIgnoreCase) &&
                (!string.IsNullOrWhiteSpace(options.NotifyUrl) || !string.IsNullOrWhiteSpace(options.NotifyUrls)) &&
                !string.IsNullOrWhiteSpace(options.NotifyTenantId) &&
                (!string.IsNullOrWhiteSpace(options.NotifyTokenFile) || !string.IsNullOrWhiteSpace(options.NotifyClientCertificateFile)));

    private static void ProbeDirectory(string path)
    {
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException();
        var probe = Path.Combine(path, ".panda-config-probe-" + Guid.NewGuid().ToString("N"));
        using var stream = new FileStream(probe, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
        stream.WriteByte(0);
        stream.Flush(flushToDisk: true);
    }
}
