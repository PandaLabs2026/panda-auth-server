using System.Security.Cryptography;
using PandaAuth.ReadinessHarness;
using Xunit;
namespace PandaAuth.Tests;
public sealed class ControlledLegacyCookieTests
{
    [Theory]
    [InlineData("--controlled-legacy-cookies-create-stdin")]
    [InlineData("--controlled-legacy-cookies-verify-stdin")]
    [InlineData("--controlled-legacy-cookies-overwrite-stdin")]
    public async Task MissingAdmissionOrUnknownCommandCannotReachOriginalStores(string command)
        =>Assert.Equal(2,await ControlledLegacyCookieProtocol.Dispatch(command,"{}"));
    [Fact]
    public void RealOriginalDpProducesVersionlessNativeCookiesWithoutChangingAnyKey()
    {
        var run=Guid.NewGuid().ToString("N");var root=Path.Combine(Path.GetTempPath(),"panda-r1-recovery-"+run);
        Directory.CreateDirectory(root);
        try
        {
            RecoveryCrypto.Create(root,run,RandomNumberGenerator.GetBytes(32));
            var before=Directory.GetFiles(root,"*.xml",SearchOption.AllDirectories).ToDictionary(path=>path,path=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
            var spec=new ControlledTransportSpec(1,run,new string('b',64),"https://auth.appliket.com/",5200,5201,5202);
            var cookies=ControlledLegacyCookies.Create(root,spec,"nonce-stamp");
            Assert.Equal(new[]{"PandaAuth.Login","PandaAuth.Login.v2","PandaAuth.Admin"},cookies.Select(cookie=>cookie.Name));
            Assert.All(cookies,cookie=>Assert.True(cookie.Value.Length>100&&cookie.Secure&&cookie.HttpOnly));
            Assert.Equal(before.OrderBy(pair=>pair.Key),Directory.GetFiles(root,"*.xml",SearchOption.AllDirectories).ToDictionary(path=>path,path=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).OrderBy(pair=>pair.Key));
            Directory.Delete(Path.Combine(root,"admin"),true);
            Assert.ThrowsAny<Exception>(()=>ControlledLegacyCookies.Create(root,spec,"nonce-stamp"));
            Assert.False(Directory.Exists(Path.Combine(root,"admin")));
        }
        finally{Directory.Delete(root,true);}
    }
}