using System.Text;
using System.Text.Json;
using PandaAuth.Server.Features.PortalClients;
using Xunit;

namespace PandaAuth.Tests;

public class PortalClientRegistrationTests
{
    [Fact]
    public void RegistrationDigest_HasExactOrderedAsciiVectorAndNoSecretOrOperationFields()
    {
        var descriptor = PortalClientRequest.Descriptor("owned-public");
        var expected = "{\"clientId\":\"owned-public\",\"clientType\":\"public\",\"consentType\":\"implicit\",\"issuer\":\"https://t0000-auth.s001.pandalabs.cn/\",\"redirectUris\":[\"https://t0000.s001.pandalabs.cn/callback\"],\"postLogoutRedirectUris\":[\"https://t0000.s001.pandalabs.cn/callback/logout\"],\"permissions\":[\"ept:authorization\",\"ept:end_session\",\"ept:token\",\"gt:authorization_code\",\"rst:code\",\"scp:profile\"],\"requirements\":[\"ft:pkce\"]}";
        Assert.Equal(expected, Encoding.UTF8.GetString(PortalClientRequest.RegistrationBytes(descriptor)));
        Assert.Equal("74fdd73c182350093242d6f905bc59c97d829a7a485981e217577d43f851051d", PortalClientRequest.RegistrationDigest(descriptor));
        descriptor.ClientSecret = "test-secret-ignored-by-digest-only";
        descriptor.Properties["operationId"] = JsonSerializer.SerializeToElement("not-digest-input");
        Assert.Equal(expected, Encoding.UTF8.GetString(PortalClientRequest.RegistrationBytes(descriptor)));
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("nested-duplicate")]
    [InlineData("schema-bool")]
    [InlineData("schema-exponent")]
    [InlineData("wrong-kind")]
    [InlineData("wrong-target")]
    [InlineData("wrong-executor")]
    [InlineData("wrong-issuer")]
    [InlineData("wrong-redirect")]
    [InlineData("wrong-logout")]
    [InlineData("short-sha")]
    [InlineData("uppercase-op")]
    [InlineData("invalid-client")]
    [InlineData("bad-utc")]
    [InlineData("window-too-long")]
    [InlineData("validity-too-long")]
    public void ClosedRequest_RejectsBadFields(string fault)
    {
        var raw = PortalClientRegistrationPostgresTests.Request();
        var fields = JsonSerializer.Deserialize<Dictionary<string, object?>>(raw)!;
        switch (fault)
        {
            case "unknown": fields["approved"] = true; break;
            case "duplicate": raw = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(raw).Replace("{", "{\"schemaVersion\":1,", StringComparison.Ordinal)); break;
            case "nested-duplicate": raw = Encoding.UTF8.GetBytes("{\"extra\":{\"x\":1,\"x\":2}}"); break;
            case "schema-bool": fields["schemaVersion"] = true; break;
            case "schema-exponent": raw = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(raw).Replace("\"schemaVersion\":1", "\"schemaVersion\":1e0", StringComparison.Ordinal)); break;
            case "wrong-kind": fields["deploymentKind"] = "ordinary"; break;
            case "wrong-target": fields["machineId"] = "other-machine"; break;
            case "wrong-executor": fields["executor"] = "other-user"; break;
            case "wrong-issuer": fields["issuer"] = "https://t0000-auth.s001.pandalabs.cn"; break;
            case "wrong-redirect": fields["redirectUri"] = "https://foreign.invalid/callback"; break;
            case "wrong-logout": fields["postLogoutRedirectUri"] = "https://foreign.invalid/callback"; break;
            case "short-sha": fields["authServerSource"] = "short"; break;
            case "uppercase-op": fields["operationId"] = "ABCDEFAB-0000-0000-0000-000000000000"; break;
            case "invalid-client": fields["clientId"] = "invalid client"; break;
            case "bad-utc": fields["maintenanceStartUtc"] = "2026-13-01T00:00:00Z"; break;
            case "window-too-long": fields["maintenanceEndUtc"] = PortalClientRequest.Timestamp(DateTimeOffset.UtcNow.AddDays(2)); break;
            case "validity-too-long": fields["validUntilUtc"] = PortalClientRequest.Timestamp(DateTimeOffset.UtcNow.AddDays(100)); break;
        }
        if (fault is not "duplicate" and not "nested-duplicate" and not "schema-exponent") raw = JsonSerializer.SerializeToUtf8Bytes(fields);
        Assert.ThrowsAny<Exception>(() => PortalClientRequest.Parse(raw, false, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Receipt_ExactlyMatchesFrozenConsumerFieldsAndOriginalDigest()
    {
        var raw = PortalClientRegistrationPostgresTests.Request();
        var request = PortalClientRequest.Parse(raw, false, DateTimeOffset.UtcNow);
        using var receipt = JsonDocument.Parse(PortalClientRequest.Receipt(request, PortalClientRequest.Descriptor("owned-public"), "created", DateTimeOffset.UtcNow));
        var expected = new[] { "schemaVersion", "deploymentKind", "tenantId", "zone", "machineId", "operationId", "requestDigest", "clientId", "result", "clientType", "consentType", "issuer", "redirectUris", "postLogoutRedirectUris", "permissions", "requirements", "registrationDigest", "authMetaSource", "authServerSource", "planReference", "executionReference", "executor", "observedUtc" };
        Assert.Equal(expected.Order(StringComparer.Ordinal), receipt.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        Assert.Equal(PortalClientRequest.Hash(raw), receipt.RootElement.GetProperty("requestDigest").GetString());
    }
}
