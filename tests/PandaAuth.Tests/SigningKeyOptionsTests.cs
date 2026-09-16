using PandaAuth.Server.Configuration;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 签名密钥周期配置的启动校验：ValidityDays 必须大于 RotationIntervalDays，
/// 否则轮换出的新密钥生效后，旧密钥会在上一轮签发的 Access Token 过期前退役，导致验签静默失败。
/// </summary>
public class SigningKeyOptionsTests
{
    [Fact]
    public void Defaults_AreValid()
    {
        new SigningKeyOptions().Validate();
    }

    [Theory]
    [InlineData(90, 180)]
    [InlineData(1, 2)]
    [InlineData(365, 366)]
    public void ValidOptions_DoNotThrow(int rotationIntervalDays, int validityDays)
    {
        var options = new SigningKeyOptions
        {
            RotationIntervalDays = rotationIntervalDays,
            ValidityDays = validityDays,
        };

        options.Validate();
    }

    [Theory]
    [InlineData(90, 90)]
    [InlineData(180, 90)]
    public void ValidityNotGreaterThanRotation_Throws(int rotationIntervalDays, int validityDays)
    {
        var options = new SigningKeyOptions
        {
            RotationIntervalDays = rotationIntervalDays,
            ValidityDays = validityDays,
        };

        var exception = Assert.Throws<InvalidOperationException>(options.Validate);

        // 异常必须写明实际取值与要求的关系，否则运维只能靠猜。
        Assert.Contains($"RotationIntervalDays={rotationIntervalDays}", exception.Message, StringComparison.Ordinal);
        Assert.Contains($"ValidityDays={validityDays}", exception.Message, StringComparison.Ordinal);
        Assert.Contains("ValidityDays > RotationIntervalDays", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0, 180)]
    [InlineData(-1, 180)]
    [InlineData(0, 0)]
    public void NonPositiveRotationInterval_Throws(int rotationIntervalDays, int validityDays)
    {
        var options = new SigningKeyOptions
        {
            RotationIntervalDays = rotationIntervalDays,
            ValidityDays = validityDays,
        };

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void NonPositiveValidity_Throws()
    {
        var options = new SigningKeyOptions
        {
            RotationIntervalDays = 90,
            ValidityDays = -1,
        };

        Assert.Throws<InvalidOperationException>(options.Validate);
    }
}
