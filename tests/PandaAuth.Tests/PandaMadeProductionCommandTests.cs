using Microsoft.Extensions.Configuration;
using PandaAuth.Server.Features.PandaMade;
using Xunit;

namespace PandaAuth.Tests;

public class PandaMadeProductionCommandTests
{
    private static IConfiguration Config(string database = "pandamade_auth", string role = "pandamade_auth_operator", string host = "pandalabs-postgres", string issuer = "https://auth.pandamade.net/")
        => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["PandaMade:Target"]="pandamade-production", ["Auth:Issuer"]=issuer,
            ["Auth:PandaMade:AdminOrigin"]="https://admin.pandamade.net/",
            ["ConnectionStrings:PandaMadeOperations"]=$"Host={host};Port=5432;Database={database};Username={role};Password=synthetic-not-production"
        }).Build();

    [Fact]
    public void RegisteredPoolAndOperatorAreAcceptedWithoutBroadeningIssuerTrust()
    {
        var value=PandaMadeProductionGuard.ValidateConfiguration(Config(),"register");
        Assert.Equal("pandamade_auth",value.Database);
        Assert.Equal("pandamade_auth_operator",value.Username);
        Assert.Equal("pandalabs-postgres",value.Host);
    }

    [Theory]
    [InlineData("panda_auth_t0000","pandamade_auth_operator","pandalabs-postgres","https://auth.pandamade.net/")]
    [InlineData("pandamade_auth","pandamade_auth_runtime","pandalabs-postgres","https://auth.pandamade.net/")]
    [InlineData("pandamade_auth","pandamade_auth_operator","localhost","https://auth.pandamade.net/")]
    [InlineData("pandamade_auth","pandamade_auth_operator","pandalabs-postgres","https://auth.servicelab.cn/")]
    public void WrongPoolPrincipalHostOrIssuerCloses(string db,string role,string host,string issuer)
        => Assert.Throws<InvalidOperationException>(()=>PandaMadeProductionGuard.ValidateConfiguration(Config(db,role,host,issuer),"register"));

    [Fact]
    public void MigrationNeedsItsOwnPrincipalAndUnknownOperationsClose()
    {
        Assert.Throws<InvalidOperationException>(()=>PandaMadeProductionGuard.ValidateConfiguration(Config(),"migrate"));
        Assert.Equal("pandamade_auth_migrator",PandaMadeProductionGuard.ValidateConfiguration(Config(role:"pandamade_auth_migrator"),"migrate").Username);
        Assert.Throws<InvalidOperationException>(()=>PandaMadeProductionGuard.ValidateConfiguration(Config(),"seed"));
    }
}
