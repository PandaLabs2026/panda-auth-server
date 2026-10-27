import io

def patch(path, pairs):
    s = io.open(path, encoding='utf-8').read()
    for old, new in pairs:
        assert old in s, f"NOT FOUND in {path}:\n{old[:140]}"
        assert s.count(old) == 1, f"NOT UNIQUE: {old[:100]}"
        s = s.replace(old, new)
    io.open(path, 'w', encoding='utf-8', newline='').write(s)
    print('patched', path)

# ---- MfaServiceTests ----
patch('tests/PandaAuth.Tests/MfaServiceTests.cs', [
    # AllowsRemovingOneOfTwoActiveFactors：两个 TOTP 撤其一
    ("""        var db = provider.GetRequiredService<PandaAuthDbContext>();
        // 两个已确认 TOTP：可验证因子口径下撤销其一不触发「最后一个因子」护栏。
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        var passkey = new MfaWebAuthnCredential { UserId = user.Id, Id = Guid.NewGuid(), CredentialId = [1], PublicKeyCose = [2] };
        db.WebAuthnCredentials.Add(passkey);
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        await service.RevokeFactorAsync(user.Id, passkey.Id, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);

        Assert.NotNull((await db.WebAuthnCredentials.SingleAsync(x => x.Id == passkey.Id)).RevokedAt);""",
     """        var db = provider.GetRequiredService<PandaAuthDbContext>();
        // 两个已确认 TOTP：可验证因子口径下撤销其一不触发「最后一个因子」护栏。
        var first = new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow };
        var second = new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow };
        db.TotpFactors.Add(first);
        db.TotpFactors.Add(second);
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        await service.RevokeFactorAsync(user.Id, first.Id, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);

        Assert.NotNull((await db.TotpFactors.SingleAsync(x => x.Id == first.Id)).RevokedAt);
        Assert.Null((await db.TotpFactors.SingleAsync(x => x.Id == second.Id)).RevokedAt);"""),
    # 恢复事件 method（两处 seed）
    ('            AuthenticationMethod = MfaClaimTypes.WebAuthn,', '            AuthenticationMethod = MfaClaimTypes.Totp,'),
    # RevokeFactor_ClearsRecoveryCodes：去掉 passkey 半段
    ("""        var db = provider.GetRequiredService<PandaAuthDbContext>();
        // 两个已确认 TOTP：可验证因子口径下撤销其一不触发「最后一个因子」护栏。
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        var passkey = new MfaWebAuthnCredential { UserId = user.Id, Id = Guid.NewGuid(), CredentialId = [1], PublicKeyCose = [2] };
        db.WebAuthnCredentials.Add(passkey);
        db.MfaRecoveryCodes.Add(new MfaRecoveryCode { UserId = user.Id, CodeHash = "00", Salt = "00" });
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        // 撤销 TOTP（可验证因子）作废恢复码；撤销退役 passkey 行（迁移动作）保留恢复码。
        var totpId = await db.TotpFactors.Where(x => x.UserId == user.Id && x.ConfirmedAt != null).Select(x => x.Id).FirstAsync();
        await service.RevokeFactorAsync(user.Id, totpId, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);
        Assert.Empty(await db.MfaRecoveryCodes.Where(code => code.UserId == user.Id).ToListAsync());

        db.MfaRecoveryCodes.Add(new MfaRecoveryCode { UserId = user.Id, CodeHash = "01", Salt = "01" });
        await db.SaveChangesAsync();
        await service.RevokeFactorAsync(user.Id, passkey.Id, Principal(user.Id, recentMethod: MfaClaimTypes.RecoveryCode), CancellationToken.None);
        Assert.Single(await db.MfaRecoveryCodes.Where(code => code.UserId == user.Id).ToListAsync());""",
     """        var db = provider.GetRequiredService<PandaAuthDbContext>();
        // 两个已确认 TOTP：撤销其一不触发「最后一个因子」护栏。
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        db.TotpFactors.Add(new MfaTotpFactor { UserId = user.Id, Id = Guid.NewGuid(), ConfirmedAt = DateTimeOffset.UtcNow });
        db.MfaRecoveryCodes.Add(new MfaRecoveryCode { UserId = user.Id, CodeHash = "00", Salt = "00" });
        await db.SaveChangesAsync();
        var service = CreateService(provider);

        // 撤销 TOTP（可验证因子）作废恢复码。
        var totpId = await db.TotpFactors.Where(x => x.UserId == user.Id && x.ConfirmedAt != null).Select(x => x.Id).FirstAsync();
        await service.RevokeFactorAsync(user.Id, totpId, Principal(user.Id, recentMethod: MfaClaimTypes.Totp), CancellationToken.None);
        Assert.Empty(await db.MfaRecoveryCodes.Where(code => code.UserId == user.Id).ToListAsync());"""),
])

# ---- MfaControllerTests ----
s = io.open('tests/PandaAuth.Tests/MfaControllerTests.cs', encoding='utf-8').read()

# OrdinaryUser：去 passkey seed 与 ActivePasskeyCount 断言
old = """        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        await SeedConfirmedTotpAsync(db, user.Id, secret);
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id,
            CredentialId = [1, 2, 3],
            PublicKeyCose = [4, 5, 6],
        });
        await db.SaveChangesAsync();
        var (context, principal) = await TestGrants.SignedInContextAsync(provider, user, MfaClaimTypes.Totp);
        var controller = CreateUserMfaController(provider, context, principal);

        var status = Assert.IsType<JsonResult>(await controller.UserStatus(CancellationToken.None));
        var value = Assert.IsType<MfaStatus>(status.Value);
        Assert.True(value.HasActiveFactor);
        Assert.Equal(1, value.ActivePasskeyCount);"""
new = """        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        await SeedConfirmedTotpAsync(db, user.Id, secret);
        await db.SaveChangesAsync();
        var (context, principal) = await TestGrants.SignedInContextAsync(provider, user, MfaClaimTypes.Totp);
        var controller = CreateUserMfaController(provider, context, principal);

        var status = Assert.IsType<JsonResult>(await controller.UserStatus(CancellationToken.None));
        var value = Assert.IsType<MfaStatus>(status.Value);
        Assert.True(value.HasActiveFactor);"""
assert old in s
s = s.replace(old, new)

# RevokeRetiredPasskeyRow 测试整体替换：撤销多 TOTP 之一须授权且成功
start = s.index('    [Fact]\n    public async Task RevokeRetiredPasskeyRow_AllowedWithoutGrant_LastTotpStillProtected()')
end = s.index('\n\n    [Fact]', start)
replacement = '''    [Fact]
    public async Task RevokeOneOfTwoTotps_WithGrant_Succeeds()
    {
        using var provider = TestUserStoreHost.Create();
        var (user, secret) = await SeedTwoTotpUserAsync(provider);
        var db2 = provider.GetRequiredService<PandaAuthDbContext>();
        var totpId = await db2.TotpFactors.AsNoTracking()
            .Where(x => x.UserId == user.Id && x.RevokedAt == null && x.ConfirmedAt != null)
            .Select(x => x.Id).SingleAsync();
        var grants = TestGrants.Create(provider);
        var issued = await grants.IssueAsync(user.Id, MfaOperations.SelfRevokeFactor, totpId.ToString(),
            new Dictionary<string, string?> { ["factorType"] = "totp" },
            TotpCode(secret), "Strong!Pass123", CancellationToken.None);
        Assert.NotNull(issued.Issued);
        var (ctx2, principal2) = await TestGrants.SignedInContextAsync(provider, user, MfaClaimTypes.Totp);
        ctx2.Request.Headers[MfaOperationGrantGate.GrantHeader] = issued.Issued!.GrantId.ToString();
        var controller2 = CreateUserMfaController(provider, ctx2, principal2);
        Assert.IsType<OkObjectResult>(await controller2.RevokeUserFactor(
            new RevokeMfaFactorRequest { FactorId = totpId }, CancellationToken.None));

        // 唯一 TOTP 不可自撤：带授权头消费成功后仍被服务层最后因子护栏拒绝。
        var (boundUser, boundSecret) = await SeedConfirmedTotpUserAsync(provider, "last-totp-member");
        var grants2 = TestGrants.Create(provider);
        var issued2 = await grants2.IssueAsync(boundUser.Id, MfaOperations.SelfRevokeFactor, totpId.ToString() /* 占位，下方取真实 id */ == "" ? "" : await db2.TotpFactors.AsNoTracking()
            .Where(x => x.UserId == boundUser.Id && x.RevokedAt == null && x.ConfirmedAt != null)
            .Select(x => x.Id).SingleAsync().ToString(),
            new Dictionary<string, string?> { ["factorType"] = "totp" },
            TotpCode(boundSecret), "Strong!Pass123", CancellationToken.None);
        Assert.NotNull(issued2.Issued);
        var (ctx3, principal3) = await TestGrants.SignedInContextAsync(provider, boundUser, MfaClaimTypes.Totp);
        ctx3.Request.Headers[MfaOperationGrantGate.GrantHeader] = issued2.Issued!.GrantId.ToString();
        var controller3 = CreateUserMfaController(provider, ctx3, principal3);
        var rejected = Assert.IsType<BadRequestObjectResult>(await controller3.RevokeUserFactor(
            new RevokeMfaFactorRequest { FactorId = await db2.TotpFactors.AsNoTracking()
            .Where(x => x.UserId == boundUser.Id && x.RevokedAt == null && x.ConfirmedAt != null)
            .Select(x => x.Id).SingleAsync() }, CancellationToken.None));
        Assert.Contains("Cannot remove the last active factor", rejected.Value!.ToString(), StringComparison.Ordinal);
    }'''
s = s[:start] + replacement + s[end:]

# UserFactors 测试：去 passkey seed
old = """        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var passkeyId = Guid.NewGuid();
        await SeedConfirmedTotpAsync(db, user.Id);
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id, Id = passkeyId, CredentialId = [7], PublicKeyCose = [8], FriendlyName = "Windows Hello",
        });
        db.WebAuthnCredentials.Add(new MfaWebAuthnCredential
        {
            UserId = user.Id, Id = Guid.NewGuid(), CredentialId = [9], PublicKeyCose = [10], RevokedAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();
        var controller = CreateUserMfaController(provider, user.Id);

        var result = Assert.IsType<JsonResult>(await controller.UserFactors(CancellationToken.None));

        var factors = Assert.IsAssignableFrom<IReadOnlyList<MfaFactorInfo>>(result.Value);
        Assert.Equal(2, factors.Count);
        Assert.Contains(factors, factor => factor.Type == "totp");
        var passkey = Assert.Single(factors, factor => factor.Type == "passkey");
        Assert.Equal(passkeyId, passkey.Id);
        Assert.Equal("Windows Hello", passkey.FriendlyName);"""
new = """        var db = provider.GetRequiredService<PandaAuthDbContext>();
        await SeedConfirmedTotpAsync(db, user.Id);
        await db.SaveChangesAsync();
        var controller = CreateUserMfaController(provider, user.Id);

        var result = Assert.IsType<JsonResult>(await controller.UserFactors(CancellationToken.None));

        var factors = Assert.IsAssignableFrom<IReadOnlyList<MfaFactorInfo>>(result.Value);
        Assert.Equal(1, factors.Count);
        Assert.Contains(factors, factor => factor.Type == "totp");"""
assert old in s, 'UserFactors'
s = s.replace(old, new)

# 加 SeedTwoTotpUserAsync 辅助（放在 SeedConfirmedTotpUserAsync 之后）
old = """    private static async Task<Guid> SeedConfirmedTotpAsync("""
new = """    private static async Task<(PandaUser User, byte[] Secret)> SeedTwoTotpUserAsync(ServiceProvider provider)
    {
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "two-totp", Email = "two-totp@example.com", EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        var db = provider.GetRequiredService<PandaAuthDbContext>();
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        await SeedConfirmedTotpAsync(db, user.Id, secret);
        await SeedConfirmedTotpAsync(db, user.Id);
        return (user, secret);
    }

    private static async Task<Guid> SeedConfirmedTotpAsync("""
assert old in s
s = s.replace(old, new)

io.open('tests/PandaAuth.Tests/MfaControllerTests.cs', 'w', encoding='utf-8', newline='').write(s)
print('MfaControllerTests rewritten')

# ---- 删 MfaPersistenceTests（整文件只测 webauthn 映射）----
import subprocess
subprocess.run(['git', 'rm', '-q', 'tests/PandaAuth.Tests/MfaPersistenceTests.cs'], check=True)
print('MfaPersistenceTests removed')

# ---- 迁移形状测试补 drop 断言 ----
patch('tests/PandaAuth.Tests/AdministratorMfaMigrationShapeTests.cs', [
    ("""        Assert.DoesNotContain(builder.Operations.OfType<DropTableOperation>(), operation =>
            operation.Name.StartsWith("AspNet", StringComparison.Ordinal));
    }""",
     """        Assert.DoesNotContain(builder.Operations.OfType<DropTableOperation>(), operation =>
            operation.Name.StartsWith("AspNet", StringComparison.Ordinal));
    }

    [Fact]
    public void DropWebAuthnCredentials_DropsRetiredTableOnly()
    {
        var builder = new MigrationBuilder("Npgsql");

        new TestDropMigration().BuildUp(builder);

        var drop = Assert.Single(builder.Operations.OfType<DropTableOperation>());
        Assert.Equal("panda_webauthn_credentials", drop.Name);
    }

    private sealed class TestDropMigration : DropWebAuthnCredentials
    {
        public void BuildUp(MigrationBuilder builder) => Up(builder);
    }"""),
])
print('PART B DONE')
