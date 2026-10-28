using System.Security.Cryptography;
using System.Text.Json;
using PandaAuth.ReadinessHarness;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ControlledCryptographyTests : IDisposable
{
    private readonly string run=Guid.NewGuid().ToString("N");
    private readonly string root;
    private readonly byte[] key=RandomNumberGenerator.GetBytes(32);
    private ControlledTransportSpec Spec => new(1,run,new string('b',64),"https://auth.appliket.com/",5200,5201,5202);
    public ControlledCryptographyTests()
    {
        root=Path.Combine(Path.GetTempPath(),"panda-r1-recovery-"+run);
        Directory.CreateDirectory(root);RecoveryCrypto.Create(root,run,key);
    }

    [Fact]
    public void ExistingThreeStoresCanRoundTripWithoutGeneratingOrChangingKeys()
    {
        var before=Files();
        var canaries=ControlledCryptography.CaptureDp(root,Spec);
        ControlledCryptography.VerifyDp(root,Spec,canaries);
        Assert.Equal(before,Files());
    }

    [Theory]
    [InlineData("server")][InlineData("admin")][InlineData("me")]
    public void MissingOriginalStoreCannotBeReplacedWithANewKey(string component)
    {
        var canaries=ControlledCryptography.CaptureDp(root,Spec);
        Directory.Delete(Path.Combine(root,component),true);
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.VerifyDp(root,Spec,canaries));
        Assert.False(Directory.Exists(Path.Combine(root,component)));
    }

    [Fact]
    public void DifferentSourceBindingOrChangedCiphertextFails()
    {
        var canaries=ControlledCryptography.CaptureDp(root,Spec);
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.VerifyDp(root,Spec with { SourceBindingSha256=new string('c',64) },canaries));
        canaries["admin"]=canaries["me"];
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.VerifyDp(root,Spec,canaries));
    }

    [Theory]
    [InlineData(KeyUse.Signing,"RS256")][InlineData(KeyUse.Encryption,"RSA-OAEP-256")]
    public void ActualPkcs8MaterialSupportsItsNativeOperation(string use,string algorithm)
    {
        using var rsa=RSA.Create(2048);var material=rsa.ExportPkcs8PrivateKey();
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(material)),ControlledCryptography.InspectRsa(use,algorithm,material));
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.InspectRsa(use,algorithm,material[..^1]));
    }

    [Fact]
    public void OriginalFactorUsesActualAadAndConfiguredKeyWithoutChangingReplayState()
    {
        var protector=new TotpSecretProtector(key,"v1");var id=Guid.NewGuid();var secret=RandomNumberGenerator.GetBytes(20);
        var cipher=protector.Protect("original-user",id,secret);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(secret)),ControlledCryptography.InspectTotp(protector,"original-user",id,cipher));
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.InspectTotp(protector,"other-user",id,cipher));
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.InspectTotp(new TotpSecretProtector(RandomNumberGenerator.GetBytes(32),"v1"),"original-user",id,cipher));
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.InspectTotp(new TotpSecretProtector(key,"v2"),"original-user",id,cipher));
    }

    [Fact]
    public void AdditionalScheduledKeysAreAllowedButOriginalsCannotDisappearOrChange()
    {
        var original=new Dictionary<string,string>{{"old","fixed"}};
        ControlledCryptography.RequireOriginals(original,new Dictionary<string,string>{{"old","fixed"},{"new","extra"}});
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.RequireOriginals(original,new Dictionary<string,string>{{"old","changed"}}));
        Assert.ThrowsAny<Exception>(()=>ControlledCryptography.RequireOriginals(original,new Dictionary<string,string>{{"new","extra"}}));
    }

    [Fact]
    public void ConnectionCannotSelectAProductionPortOrASeparateNamespace()
    {
        foreach(var value in new[]{"Host=127.0.0.1;Port=5432;Database=panda_auth_fleet;Username=panda_auth_fleet_runtime;Password=private",
            "Host=192.0.2.1;Port=55432;Database=panda_auth_fleet;Username=panda_auth_fleet_runtime;Password=private",
            "Host=127.0.0.1;Port=55432;Database=postgres;Username=postgres;Password=private"})
            Assert.ThrowsAny<Exception>(()=>ControlledCryptography.Connection(value));
        Assert.Throws<JsonException>(()=>ControlledTransport.Decode<ControlledCryptoInput>("{\"scope\":\"production\"}"));
    }

    private KeyValuePair<string,string>[] Files()=>Directory.GetFiles(root,"*.xml",SearchOption.AllDirectories).Order()
        .Select(path=>new KeyValuePair<string,string>(path,Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))))).ToArray();
    public void Dispose()=>Directory.Delete(root,true);
}
