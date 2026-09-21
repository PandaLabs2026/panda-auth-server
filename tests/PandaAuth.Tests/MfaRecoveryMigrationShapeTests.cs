using Microsoft.EntityFrameworkCore;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;

namespace PandaAuth.Tests;

public sealed class MfaRecoveryMigrationShapeTests
{
    [Fact]
    public void RecoveryCode_MapsToDedicatedTableWithUserForeignKeyAndNoPlaintextCode()
    {
        using var db = new DesignTimeDbContextFactory().CreateDbContext([]);
        var entity = db.Model.FindEntityType(typeof(MfaRecoveryCode));

        Assert.NotNull(entity);
        Assert.Equal("panda_mfa_recovery_codes", entity.GetTableName());
        Assert.Contains(entity.GetProperties(), property => property.Name == nameof(MfaRecoveryCode.CodeHash));
        Assert.Contains(entity.GetProperties(), property => property.Name == nameof(MfaRecoveryCode.ConsumedAt));
        Assert.DoesNotContain(entity.GetProperties(), property =>
            string.Equals(property.Name, "Code", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(entity.GetForeignKeys(), foreignKey =>
            foreignKey.PrincipalEntityType.ClrType == typeof(PandaUser) &&
            foreignKey.Properties.Single().Name == nameof(MfaRecoveryCode.UserId));
    }
}
