using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>One-shot tooling adapter. The running server uses SigningKeyRing and its refresh service.</summary>
public static class SigningKeyStore
{
    public static async Task<List<(SigningKeyRecord Record, RsaSecurityKey Key)>> LoadOrCreateAsync(
        string connectionString, SigningKeyOptions options)
    {
        var ring = new SigningKeyRing(connectionString, options, TimeProvider.System);
        await ring.RefreshAsync();
        await using var db = new PandaAuthDbContext(new DbContextOptionsBuilder<PandaAuthDbContext>().UseNpgsql(connectionString).Options);
        var records = await db.SigningKeys.AsNoTracking().ToDictionaryAsync(key => key.KeyId);
        return ring.Snapshot.Keys.Select(key => (records[key.Id], key.PrivateKey)).ToList();
    }
}
