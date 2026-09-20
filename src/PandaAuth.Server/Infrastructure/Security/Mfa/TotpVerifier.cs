using System.Security.Cryptography;
using System.Text;

namespace PandaAuth.Server.Infrastructure.Security.Mfa;

public static class TotpVerifier
{
    private const long PeriodSeconds = 30;

    public static bool TryVerify(
        byte[] secret,
        string code,
        DateTimeOffset now,
        long? lastAcceptedTimeStep,
        out long acceptedTimeStep)
    {
        acceptedTimeStep = default;
        if (code.Length != 6 || code.Any(character => !char.IsAsciiDigit(character)))
        {
            return false;
        }

        var currentStep = now.ToUnixTimeSeconds() / PeriodSeconds;
        for (var offset = -1; offset <= 1; offset++)
        {
            var step = currentStep + offset;
            if (lastAcceptedTimeStep is not null && step <= lastAcceptedTimeStep.Value)
            {
                continue;
            }

            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(code),
                    Encoding.ASCII.GetBytes(CodeFor(secret, step))))
            {
                acceptedTimeStep = step;
                return true;
            }
        }

        return false;
    }

    private static string CodeFor(byte[] secret, long timeStep)
    {
        Span<byte> counter = stackalloc byte[8];
        for (var index = counter.Length - 1; index >= 0; index--)
        {
            counter[index] = (byte)timeStep;
            timeStep >>= 8;
        }

        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) |
                     (hash[offset + 1] << 16) |
                     (hash[offset + 2] << 8) |
                     hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}
