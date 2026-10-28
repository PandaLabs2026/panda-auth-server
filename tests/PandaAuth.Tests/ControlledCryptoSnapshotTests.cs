using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using PandaAuth.ReadinessHarness;

namespace PandaAuth.Tests;
public sealed class ControlledCryptoSnapshotTests
{
    [Fact]
    public void FingerprintMatchesControllerNullDelimitedBinding()
    {
        var owner=new string('a',64);
        var expected=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("panda-auth-controlled-db-v1\0"+owner+"\0"+"127.0.0.1\055432\0panda_auth_fleet\042")));
        Assert.Equal(expected,ControlledCryptoSnapshot.Fingerprint("panda_auth_fleet","42",owner));
        Assert.NotEqual(expected,ControlledCryptoSnapshot.Fingerprint("panda_auth_fleet","42",new string('b',64)));
    }
    [Fact]
    public void StableIdentityIncludesEveryImmutableFieldAndIsUnambiguous()
    {
        Assert.NotEqual(ControlledCryptoSnapshot.Hash("ab","c"),ControlledCryptoSnapshot.Hash("a","bc"));
        Assert.NotEqual(ControlledCryptoSnapshot.Hash("id","key"),ControlledCryptoSnapshot.Hash("id","changed"));
    }
    [Fact]
    public async Task ControlledCommandRejectsOutsideIsolatedNamespaceBeforeDatabaseAccess()
    {
        var spec=new ControlledTransportSpec(1,Guid.NewGuid().ToString("N"),new string('b',64),"https://auth.appliket.com/",5200,5201,5202);
        var input=new ControlledCryptoInput(spec,"Host=192.0.2.1;Password=private",new string('a',64),Convert.ToBase64String(new byte[32]),"v1");
        await Assert.ThrowsAnyAsync<Exception>(()=>ControlledCryptoSnapshot.Read(input));
    }
}
