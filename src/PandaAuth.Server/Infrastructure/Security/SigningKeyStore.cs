using System.Buffers.Text;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
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
            records.Add(await CreateAndInsertAsync(context, KeyUse.Encryption, "RSA-OAEP-256", now, options));
        }

        // 签名密钥：无密钥，或最新密钥已超出轮换周期时生成新密钥。
        var signingKeys = records
            .Where(r => r.Use == KeyUse.Signing)
            .OrderByDescending(r => r.NotBefore)
            .ToList();

        if (signingKeys.Count == 0 || now - signingKeys[0].NotBefore >= TimeSpan.FromDays(options.RotationIntervalDays))
        {
            var newSigningKey = await CreateAndInsertAsync(context, KeyUse.Signing, "RS256", now, options);
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

    /// <summary>
    /// 生成并落库一把新密钥。KeyId（公钥 SHA256 指纹）是主键——同指纹重复插入（如备份恢复重放）
    /// 触发主键冲突时读取已存在记录继续，不让启动失败。注意：双实例同时冷启动生成的是两把
    /// 不同的随机密钥、指纹不同，主键唯一性拦不住（单实例架构假设内不发生；见部署文档）。
    /// 异步 SaveChanges：启动路径其余步骤均已异步，同步保存会在容器启动时阻塞线程池线程。
    /// </summary>
    private static async Task<SigningKeyRecord> CreateAndInsertAsync(
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
        try
        {
            await context.SaveChangesAsync();
        }
        catch (DbUpdateException exception) when (
            exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            // 同指纹（主键）冲突：以先落库者为准。游离失败实体，避免同一键双实例被跟踪。
            context.Entry(record).State = EntityState.Detached;
            var existing = await context.SigningKeys.AsNoTracking()
                .SingleAsync(key => key.KeyId == record.KeyId);
            return existing;
        }
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
