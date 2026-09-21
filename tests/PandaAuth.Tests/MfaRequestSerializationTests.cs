using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Fido2NetLib.Serialization;
using PandaAuth.Server.Features.Account;
using Xunit;

namespace PandaAuth.Tests;

public class MfaRequestSerializationTests
{
    [Fact]
    public void BrowserAttestationPayload_BindsToFidoRequest()
    {
        const string json = "{\"ceremonyId\":\"00000000-0000-0000-0000-000000000001\",\"response\":{\"id\":\"AQID\",\"rawId\":\"AQID\",\"type\":\"public-key\",\"response\":{\"clientDataJson\":\"AQID\",\"AttestationObject\":\"BAUG\"},\"clientExtensionResults\":{}}}";

        var request = JsonSerializer.Deserialize<CompletePasskeyEnrollmentRequest>(json, FidoJsonOptions());

        Assert.NotNull(request);
        Assert.NotNull(request!.Response);
        Assert.Equal([1, 2, 3], request.Response!.RawId);
        Assert.Equal([1, 2, 3], request.Response.Response.ClientDataJson);
        Assert.Equal([4, 5, 6], request.Response.Response.AttestationObject);
    }

    [Fact]
    public void BrowserAssertionPayload_BindsToFidoRequest()
    {
        const string json = "{\"ceremonyId\":\"00000000-0000-0000-0000-000000000001\",\"response\":{\"id\":\"AQID\",\"rawId\":\"AQID\",\"type\":\"public-key\",\"response\":{\"clientDataJson\":\"AQID\",\"authenticatorData\":\"BAUG\",\"signature\":\"BwgJ\",\"userHandle\":\"CgsM\"},\"clientExtensionResults\":{}}}";

        var request = JsonSerializer.Deserialize<CompletePasskeyAssertionRequest>(json, FidoJsonOptions());

        Assert.NotNull(request);
        Assert.NotNull(request!.Response);
        Assert.Equal([1, 2, 3], request.Response!.RawId);
        Assert.Equal([1, 2, 3], request.Response.Response.ClientDataJson);
        Assert.Equal([4, 5, 6], request.Response.Response.AuthenticatorData);
        Assert.Equal([7, 8, 9], request.Response.Response.Signature);
        Assert.Equal([10, 11, 12], request.Response.Response.UserHandle);
    }

    private static JsonSerializerOptions FidoJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.TypeInfoResolverChain.Insert(0, FidoModelSerializerContext.Default);
        options.TypeInfoResolverChain.Add(new DefaultJsonTypeInfoResolver());
        return options;
    }
}
