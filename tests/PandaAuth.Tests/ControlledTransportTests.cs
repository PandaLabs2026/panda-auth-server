using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using PandaAuth.ReadinessHarness;
using Xunit;

namespace PandaAuth.Tests;

public sealed class ControlledTransportTests
{
    private static readonly ControlledTransportSpec Valid = new(1, new string('a', 32), new string('b', 64),
        "https://auth.appliket.com/", 5200, 5201, 5202);

    [Theory]
    [InlineData("http://auth.appliket.com/")]
    [InlineData("https://auth.appliket.com:8443/")]
    [InlineData("https://user:private@auth.appliket.com/")]
    [InlineData("https://auth.appliket.com/path")]
    [InlineData("https://auth.appliket.com/?x=1")]
    [InlineData("https://127.0.0.1/")]
    public void SpecRejectsUnboundIssuerForms(string issuer) => Assert.Throws<InvalidOperationException>(() =>
        ControlledTransport.Validate(Valid with { Issuer = issuer }));

    [Fact]
    public void SpecRejectsDuplicateOrDatabasePortsAndWrongBinding()
    {
        Assert.Throws<InvalidOperationException>(() => ControlledTransport.Validate(Valid with { MePort = 5200 }));
        Assert.Throws<InvalidOperationException>(() => ControlledTransport.Validate(Valid with { ServerPort = 55432 }));
        Assert.Throws<InvalidOperationException>(() => ControlledTransport.Validate(Valid with { Attempt = "production" }));
        Assert.Throws<InvalidOperationException>(() => ControlledTransport.Validate(Valid with { SourceBindingSha256 = "unknown" }));
    }

    [Fact]
    public void CanonicalSpecMatchesControllerEncoding()
    {
        var encoded = ControlledTransport.Canonical(Valid);
        Assert.Equal("{\"schema\":1,\"attempt\":\""+new string('a',32)+"\",\"sourceBindingSha256\":\""+new string('b',64)+
            "\",\"issuer\":\"https://auth.appliket.com/\",\"serverPort\":5200,\"adminPort\":5201,\"mePort\":5202}", encoded);
    }

    [Theory]
    [InlineData("/admin", 5201)]
    [InlineData("/admin/healthz", 5201)]
    [InlineData("/me/healthz", 5202)]
    [InlineData("/administrator", 5200)]
    [InlineData("//foreign.example/admin", 5200)]
    public void RouteRemainsInsideTheThreeLoopbackPorts(string path, int port)
    {
        Assert.Equal(port, ControlledTransport.SelectPort(Valid, new PathString(path)));
        var target = ControlledTransport.Target(Valid, new PathString(path), new QueryString("?next=https://foreign.example"));
        Assert.True(target.IsLoopback);
        Assert.Equal(port, target.Port);
    }

    [Fact]
    public void NewAuthorityHasOriginalDnsSanAndAnIndependentPrivateRoot()
    {
        const string password = "synthetic-controlled-tls-password";
        var material = ControlledTransport.Certificates(Valid, password);
        using var root = X509Certificate2.CreateFromPem(material.RootPem);
        using var leaf = X509CertificateLoader.LoadPkcs12(material.Pfx, password);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(chain.Build(leaf));
        Assert.Equal("auth.appliket.com", leaf.GetNameInfo(X509NameType.DnsName, false));
        Assert.False(root.HasPrivateKey);
        Assert.True(leaf.HasPrivateKey);
    }

    [Fact]
    public void DuplicateAndUnknownInputFieldsDoNotSelectAnotherExecutionMode()
    {
        var spec = ControlledTransport.Canonical(Valid);
        Assert.Throws<JsonException>(() => ControlledTransport.Parse("{\"spec\":"+spec+",\"spec\":"+spec+"}"));
        Assert.Throws<JsonException>(() => ControlledTransport.Parse("{\"spec\":"+spec+",\"scope\":\"production\"}"));
    }

    [Fact]
    public void OrdinaryProcessCannotOptIntoControlledTransportWithJsonAlone()
    {
        var attempt = Environment.GetEnvironmentVariable("PANDA_AUTH_CONTROLLED_ATTEMPT") == new string('c',32) ? new string('d',32) : new string('c',32);
        Assert.Throws<InvalidOperationException>(() => ControlledTransport.Guard(Valid with { Attempt=attempt }));
    }
}
