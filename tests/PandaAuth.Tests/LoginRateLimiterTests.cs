using Xunit;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;

namespace PandaAuth.Tests;

public class LoginRateLimiterTests : IDisposable
{
    private readonly LoginRateLimiter _limiter = new(Options.Create(new AuthOptions
    {
        RateLimit = new RateLimitOptions
        {
            IpPerMinute = 3,
            AccountPerMinute = 2,
        },
    }));

    [Fact]
    public void Account_OverLimit_IsRejected()
    {
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.False(_limiter.AttemptByAccount("user-a").IsAcquired);
    }

    [Fact]
    public void Accounts_AreLimitedIndependently()
    {
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.False(_limiter.AttemptByAccount("user-a").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-b").IsAcquired);
    }

    [Fact]
    public void AccountKey_IsCaseInsensitive()
    {
        Assert.True(_limiter.AttemptByAccount("User-A").IsAcquired);
        Assert.True(_limiter.AttemptByAccount("user-A").IsAcquired);
        Assert.False(_limiter.AttemptByAccount("USER-a").IsAcquired);
    }

    [Fact]
    public void Ip_OverLimit_IsRejected()
    {
        Assert.True(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
        Assert.True(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
        Assert.True(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
        Assert.False(_limiter.AttemptByIp("10.1.1.1").IsAcquired);
    }

    [Fact]
    public void MissingIp_FallsBackToSharedBucket()
    {
        Assert.True(_limiter.AttemptByIp(null).IsAcquired);
        Assert.True(_limiter.AttemptByIp(null).IsAcquired);
        Assert.True(_limiter.AttemptByIp(null).IsAcquired);
        Assert.False(_limiter.AttemptByIp(null).IsAcquired);
    }

    public void Dispose() => _limiter.Dispose();
}
