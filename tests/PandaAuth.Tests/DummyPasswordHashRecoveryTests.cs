using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class DummyPasswordHashRecoveryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Transient_first_computation_does_not_poison_the_shared_dummy(bool canceled)
    {
        var hasher = new TransientHasher(canceled);
        var services = new ServiceCollection();
        services.AddScoped<IPasswordHasher>(_ => hasher);
        services.AddSingleton<DummyPasswordHash>();
        using var provider = services.BuildServiceProvider();
        var dummy = provider.GetRequiredService<DummyPasswordHash>();
        if (canceled) Assert.Throws<OperationCanceledException>(() => dummy.Value);
        else Assert.Throws<PasswordHashCapacityException>(() => dummy.Value);
        Assert.Equal("synthetic-hash", dummy.Value);
        Assert.Equal("synthetic-hash", dummy.Value);
        Assert.Equal(2, hasher.Calls);
    }

    private sealed class TransientHasher(bool canceled) : IPasswordHasher
    {
        public int Calls { get; private set; }
        public string Hash(string password)
        {
            if (++Calls == 1)
            {
                if (canceled) throw new OperationCanceledException();
                throw new PasswordHashCapacityException();
            }
            return "synthetic-hash";
        }
        public PasswordVerificationOutcome Verify(string? hashedPassword, string providedPassword)
            => throw new NotSupportedException();
    }
}
