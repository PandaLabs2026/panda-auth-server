using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public class MfaPersistenceTests
{
    [Fact]
    public void WebAuthnCredential_MapsToSelfOwnedTableWithUniqueCredentialId()
    {
        using var db = new DesignTimeDbContextFactory().CreateDbContext([]);

        var entity = db.Model.FindEntityType(typeof(MfaWebAuthnCredential));

        Assert.NotNull(entity);
        Assert.Equal("panda_webauthn_credentials", entity.GetTableName());
        Assert.Contains(entity.GetIndexes(), index =>
            index.IsUnique && index.Properties.Single().Name == nameof(MfaWebAuthnCredential.CredentialId));
    }

    [Fact]
    public void TotpFactor_MapsToSelfOwnedTableWithoutPlaintextSecret()
    {
        using var db = new DesignTimeDbContextFactory().CreateDbContext([]);

        var entity = db.Model.FindEntityType(typeof(MfaTotpFactor));

        Assert.NotNull(entity);
        Assert.Equal("panda_totp_factors", entity.GetTableName());
        Assert.DoesNotContain(entity.GetProperties(), property =>
            string.Equals(property.Name, "Secret", StringComparison.OrdinalIgnoreCase));
    }
}
