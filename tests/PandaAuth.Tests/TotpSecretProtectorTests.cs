using System.Security.Cryptography;
using PandaAuth.Server.Infrastructure.Security.Mfa;
using Xunit;

namespace PandaAuth.Tests;

public class TotpSecretProtectorTests
{
    [Fact]
    public void CiphertextTampering_IsRejected()
    {
        var protector = new TotpSecretProtector(Enumerable.Repeat((byte)7, 32).ToArray(), "v1");
        var factorId = Guid.NewGuid();
        var protectedSecret = protector.Protect("user-1", factorId, [1, 2, 3]);
        protectedSecret.Ciphertext[0] ^= 1;

        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect("user-1", factorId, protectedSecret));
    }
}
