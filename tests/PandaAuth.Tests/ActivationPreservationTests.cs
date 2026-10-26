using System.Text.Json.Nodes;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;
namespace PandaAuth.Tests;
public sealed class ActivationPreservationTests
{
    private static string Application(string secret,string permission,string token="original") => new JsonObject
    { ["ClientId"]=FirstPartyClients.AdminWeb,["ClientSecret"]=secret,["Permissions"]=permission,["ConcurrencyToken"]=token,["RedirectUris"]="[\"https://callback.invalid/\"]" }.ToJsonString();
    [Fact]
    public void OnlyExpectedAdminGrantAndItsConcurrencyTokenAreIgnored()
    {
        var permission="scp:"+PandaAuthAdminApi.Scope;
        var before=Application("original","[]");
        var after=Application("original","[\""+permission+"\"]","changed");
        Assert.Equal(ActivationPreservation.Normalize("OpenIddictApplications",before,true),ActivationPreservation.Normalize("OpenIddictApplications",after,true));
        Assert.NotEqual(ActivationPreservation.Normalize("OpenIddictApplications",before,true),ActivationPreservation.Normalize("OpenIddictApplications",Application("changed","[]"),true));
        Assert.NotEqual(ActivationPreservation.Normalize("OpenIddictApplications",before,false),ActivationPreservation.Normalize("OpenIddictApplications",after,false));
    }
    [Fact]
    public void OtherClientsAndHumanStateRemainFullyProtected()
    {
        var before=Application("original","[]").Replace(FirstPartyClients.AdminWeb,"other-client");
        var after=before.Replace("original","changed");
        Assert.NotEqual(ActivationPreservation.Normalize("OpenIddictApplications",before,true),ActivationPreservation.Normalize("OpenIddictApplications",after,true));
        Assert.NotEqual(ActivationPreservation.Normalize("panda_users","{\"stamp\":\"a\"}",true),ActivationPreservation.Normalize("panda_users","{\"stamp\":\"b\"}",true));
    }
    [Fact]
    public void LifecycleColumnsAreExcludedWithoutMaskingOriginalMaterial()
    {
        Assert.Equal(ActivationPreservation.Normalize("signing_keys","{\"PrivateKey\":\"old\"}",false),ActivationPreservation.Normalize("signing_keys","{\"PrivateKey\":\"old\",\"VerifyUntil\":null}",false));
        Assert.NotEqual(ActivationPreservation.Normalize("signing_keys","{\"PrivateKey\":\"old\"}",false),ActivationPreservation.Normalize("signing_keys","{\"PrivateKey\":\"new\"}",false));
    }
}
