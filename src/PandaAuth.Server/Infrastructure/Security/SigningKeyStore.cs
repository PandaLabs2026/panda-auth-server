using System.Buffers.Text;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Persistence;

namespace PandaAuth.Server.Infrastructure.Security;

public static class SigningKeyStore
{
    /// <summary>
    /// 启动前从数据库加载签名/加密密钥：无密钥则生成，超出轮换周期则生成新密钥，过期密钥自动退役。
    /// OpenIddict 要求在 DI 容器构建前完成密钥注册，因此该方法直接持有连接字符串创建临时 DbContext。
    /// </summary>
    public static async Task<List<(SigningKeyRecord Record, RsaSecurityKey Key)>> LoadOrCreateAsync(
        string connectionString, SigningKeyOptions options)
    {
        var now = DateTimeOffset.UtcNow;
        await using var context = CreateContext(connectionString);
        var records = await context.SigningKeys.ToListAsync();

        // 加密密钥只创建、永不轮换：轮换加密密钥会使未过期的刷新令牌与授权码全部失效。
        if (records.All(r => r.Use != KeyUse.Encryption))
        {
            records.Add(CreateAndInsert(context, KeyUse.Encryption, "RSA-OAEP-256", now, options));
        }

        // 签名密钥：无密钥，或最新密钥已超出轮换周期时生成新密钥。
        var signingKeys = records
            .Where(r => r.Use == KeyUse.Signing)
            .OrderByDescending(r => r.NotBefore)
            .ToList();

        if (signingKeys.Count == 0 || now - signingKeys[0].NotBefore >= TimeSpan.FromDays(options.RotationIntervalDays))
        {
            var newSigningKey = CreateAndInsert(context, KeyUse.Signing, "RS256", now, options);
            signingKeys.Insert(0, newSigningKey);
            records.Add(newSigningKey);
        }

        // 退役超出有效期的旧签名密钥；有效期大于轮换周期，保证旧 Access Token 在过期前仍可验签。
        foreach (var key in signingKeys.Where(key => now > key.NotAfter))
        {
            key.Retired = true;
        }

        await context.SaveChangesAsync();

        return records
            .Where(r => !r.Retired)
            .Select(r => (r, CreateSecurityKey(r)))
            .ToList();
    }

    private static SigningKeyRecord CreateAndInsert(
        PandaAuthDbContext context, string use, string algorithm, DateTimeOffset now, SigningKeyOptions options)
    {
        using var rsa = RSA.Create(2048);
        var record = new SigningKeyRecord
        {
            KeyId = Base64Url.EncodeToString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())),
            Use = use,
            Algorithm = algorithm,
            PrivateKey = rsa.ExportPkcs8PrivateKey(),
            NotBefore = now,
            NotAfter = now.AddDays(options.ValidityDays),
        };
        context.SigningKeys.Add(record);
        context.SaveChanges();
        return record;
    }

    private static RsaSecurityKey CreateSecurityKey(SigningKeyRecord record)
    {
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(record.PrivateKey, out _);
        return new RsaSecurityKey(rsa) { KeyId = record.KeyId };
    }

    private static PandaAuthDbContext CreateContext(string connectionString)
    {
        var options = new DbContextOptionsBuilder<PandaAuthDbContext>()
            .UseNpgsql(connectionString)
            .Options;
        return new PandaAuthDbContext(options);
    }
}
