using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Server.Configuration;

namespace PandaAuth.CloudConfig.JointFixture;

// A separate process permits real connection loss before/after the production security transaction commits.
internal static class AccountSecurityProbe
{
    internal sealed record Input(string Connection, string UserId, bool BeforeCommit);

    internal static async Task<int> RunAsync(bool keyRefresh = false)
    {
        try
        {
            var line = await Console.In.ReadLineAsync();
            if (line is null || line.Length > 4096) return 78;
            var input = JsonSerializer.Deserialize<Input>(line) ?? throw new InvalidOperationException();
            var endpoint = new NpgsqlConnectionStringBuilder(input.Connection);
            var shared = Environment.GetEnvironmentVariable("PANDA_AUTH_TEST_SHARED_POSTGRES") == "1"
                && endpoint.Port == 5432 && Regex.IsMatch(endpoint.Username ?? "", "^panda_auth_quality_runner_[0-9a-f]{16}$");
            if (endpoint.Host != "127.0.0.1" || (!shared && endpoint.Port != 43823)
                || !Regex.IsMatch(endpoint.Database ?? "", "^panda_protocol_test_[0-9a-f]{32}$"))
                throw new InvalidOperationException();
            if (keyRefresh)
            {
                var keys = await SigningKeyStore.LoadOrCreateAsync(endpoint.ConnectionString, new SigningKeyOptions());
                Console.WriteLine(JsonSerializer.Serialize(keys.Select(key => key.Record.KeyId).Order()));
                return 0;
            }
            await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>()
                .UseNpgsql(endpoint.ConnectionString).UseOpenIddict().Options);
            var users = new UserService(db, new Argon2idPasswordHasher(), TimeProvider.System);
            var user = await users.FindByIdAsync(input.UserId) ?? throw new InvalidOperationException();
            var events = new SecurityEventWriter(db, TimeProvider.System);
            var revoker = new ProbeRevoker(new TokenRevocationService(db, events), input.BeforeCommit);
            var security = new SessionSecurityService(users, revoker, events);
            var result = await security.InvalidateUserAsync(user, "process_probe", user.Id);
            if (!result.Succeeded) throw new InvalidOperationException();
            Console.WriteLine("after_commit");
            await Task.Delay(Timeout.InfiniteTimeSpan);
            return 0;
        }
        catch
        {
            Console.Error.WriteLine("ACCOUNT_SECURITY_PROBE_REJECTED");
            return 78;
        }
    }

    private sealed class ProbeRevoker(ITokenRevoker inner, bool pause) : ITokenRevoker
    {
        public async Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
        {
            await inner.RevokeUserTokensAsync(userId, clientId, cancellationToken);
            if (pause)
            {
                Console.WriteLine("before_commit");
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
        }
        public Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
