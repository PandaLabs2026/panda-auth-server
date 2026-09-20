using PandaAuth.Server.Configuration;
using Xunit;

namespace PandaAuth.Tests;

public class MfaOptionsTests
{
    [Fact]
    public void ProductionWithoutTotpEncryptionKey_FailsValidation()
    {
        var options = new MfaOptions();

        Assert.Throws<InvalidOperationException>(() => options.Validate(production: true));
    }

    [Fact]
    public void Base64Encoded32ByteKey_PassesValidation()
    {
        var options = new MfaOptions
        {
            TotpEncryptionKey = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()),
        };

        options.Validate(production: true);
    }
}
