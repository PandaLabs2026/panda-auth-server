using Fido2NetLib;

namespace PandaAuth.Server.Configuration;

/// <summary>Derives the WebAuthn RP binding from the canonical OIDC issuer, preventing a second domain source.</summary>
public static class WebAuthnRelyingParty
{
    public static Fido2Configuration Create(string issuer)
    {
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var uri) ||
            (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) && !uri.IsLoopback) ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new InvalidOperationException("Auth:Issuer 必须是 HTTPS 绝对 URI（仅 loopback 开发环境可用 HTTP），才能作为 WebAuthn 来源。");
        }

        return new Fido2Configuration
        {
            ServerDomain = uri.Host,
            ServerName = "PandaAuth",
            Origins = new HashSet<string> { uri.GetLeftPart(UriPartial.Authority) },
        };
    }
}
