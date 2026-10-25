using System.Security.Cryptography;

namespace PandaAuth.ReadinessHarness;

public static class BffSnapshot
{
    public static Uri ResolveOwnedRedirect(Uri owner, Uri location)
    {
        var target = new Uri(owner, location);
        if (target.Scheme != Uri.UriSchemeHttps || target.UserInfo.Length > 0 || target.GetLeftPart(UriPartial.Authority) != owner.GetLeftPart(UriPartial.Authority))
            throw new InvalidOperationException("readiness_bff_redirect_outside_fixture");
        return target;
    }

    public static string TotpCode(byte[] secret, DateTimeOffset now)
    {
        var step = now.ToUnixTimeSeconds() / 30;
        Span<byte> counter = stackalloc byte[8];
        for (var index = counter.Length - 1; index >= 0; index--) { counter[index] = (byte)step; step >>= 8; }
        var hash = HMACSHA1.HashData(secret, counter);
        var offset = hash[^1] & 15;
        var binary = ((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}
