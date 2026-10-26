using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using PandaAuth.ReadinessHarness;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;
namespace PandaAuth.Tests;
public sealed class ControlledLegacyTokenTests
{
    [Theory]
    [InlineData("--controlled-legacy-tokens-create-stdin")]
    [InlineData("--controlled-legacy-tokens-verify-stdin")]
    [InlineData("--controlled-legacy-tokens-overwrite-stdin")]
    public async Task MissingAdmissionOrUnknownCommandCannotAccessAnyTokenStore(string command)
        =>Assert.Equal(2,await ControlledLegacyTokenProtocol.Dispatch(command,"{}"));
    [Fact]
    public async Task NativeGeneratorCreatesStoredVersionlessTokensAndRejectsDamagedCiphertext()
    {
        var run=Guid.NewGuid().ToString("N");var spec=new ControlledTransportSpec(1,run,new string('b',64),"https://auth.appliket.com/",5200,5201,5202);
        using var signing=RSA.Create(2048);using var encryption=RSA.Create(2048);
        var services=new ServiceCollection().AddLogging();
        services.AddDbContext<PandaAuthDbContext>(options=>options.UseInMemoryDatabase("legacy-token-"+run).UseOpenIddict());
        services.AddOpenIddict().AddCore(options=>options.UseEntityFrameworkCore().UseDbContext<PandaAuthDbContext>())
            .AddServer(options=>{options.SetIssuer(spec.Issuer).SetTokenEndpointUris("/connect/token").AllowRefreshTokenFlow();
                options.AddSigningKey(new RsaSecurityKey(signing){KeyId="original-signing"});
                options.AddEncryptionKey(new RsaSecurityKey(encryption){KeyId="original-encryption"});});
        await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
        var manager=scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(new OpenIddictApplicationDescriptor{ClientId=ControlledActors.Names(spec)[3],ClientSecret="synthetic-only",ClientType="confidential"});
        foreach(var type in new[]{OpenIddictConstants.TokenTypeIdentifiers.AccessToken,OpenIddictConstants.TokenTypeIdentifiers.RefreshToken})
        {
            var token=await ControlledLegacyTokens.Generate(scope.ServiceProvider,spec,type);
            Assert.True(token.Length>100);
            await ControlledLegacyTokens.Verify(scope.ServiceProvider,spec,type,token);
            await Assert.ThrowsAnyAsync<Exception>(()=>ControlledLegacyTokens.Verify(scope.ServiceProvider,spec,type,token[..^12]+"invalid"));
            var wrong=type==OpenIddictConstants.TokenTypeIdentifiers.AccessToken?OpenIddictConstants.TokenTypeIdentifiers.RefreshToken:OpenIddictConstants.TokenTypeIdentifiers.AccessToken;
            await Assert.ThrowsAnyAsync<Exception>(()=>ControlledLegacyTokens.Verify(scope.ServiceProvider,spec,wrong,token));
        }
    }
}