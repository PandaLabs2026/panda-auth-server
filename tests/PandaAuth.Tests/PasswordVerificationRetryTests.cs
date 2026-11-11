using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Domain;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PasswordVerificationRetryTests
{
    [Theory]
    [InlineData("metadata", 1, true)]
    [InlineData("password", 2, false)]
    [InlineData("same-password-new-hash", 2, true)]
    [InlineData("frozen", 1, false)]
    [InlineData("lockout", 1, false)]
    [InlineData("mfa", 1, false)]
    public async Task Retry_reuses_only_an_unchanged_hash_and_rechecks_account_state(string change, int calls, bool success)
    {
        var hasher = new CountingHasher();
        using var provider = TestUserStoreHost.Create(passwordHasher: hasher);
        var users = provider.GetRequiredService<UserService>();
        var user = new PandaUser { UserName = "synthetic-retry-user" };
        Assert.True((await users.CreateAsync(user, "Strong!Pass123")).Succeeded);
        using var scope = provider.CreateScope();
        var other = scope.ServiceProvider.GetRequiredService<UserService>();
        var stale = (await other.FindByIdAsync(user.Id))!;
        switch (change)
        {
            case "password": user.PasswordHash = hasher.Hash("NewStrong!Pass123"); break;
            case "same-password-new-hash": user.PasswordHash = hasher.Hash("Strong!Pass123"); break;
            case "frozen": user.Status = UserStatus.Frozen; break;
            case "lockout": user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(5); break;
            case "mfa": user.TwoFactorEnabled = true; break;
            default: user.Nickname = "concurrent metadata"; break;
        }
        Assert.True((await users.UpdateAsync(user)).Succeeded);
        var result = await scope.ServiceProvider.GetRequiredService<LoginSessionService>()
            .CheckPasswordSignInAsync(stale, "Strong!Pass123", lockoutOnFailure: true);
        Assert.Equal(success, result.Succeeded);
        Assert.Equal(calls, hasher.VerifyCalls);
        if (change == "lockout") Assert.True(result.IsLockedOut);
        if (change == "mfa") Assert.True(result.RequiresMfaReconfiguration);
        if (change == "frozen") Assert.True(result.IsNotAllowed);
    }

    private sealed class CountingHasher : IPasswordHasher
    {
        private readonly Dictionary<string, string> passwords = [];
        public int VerifyCalls { get; private set; }
        public string Hash(string password)
        {
            var id = Guid.NewGuid().ToString("N");
            passwords.Add(id, password);
            return id;
        }
        public PasswordVerificationOutcome Verify(string? hashedPassword, string providedPassword)
        {
            VerifyCalls++;
            return hashedPassword is not null && passwords.TryGetValue(hashedPassword, out var password) && password == providedPassword
                ? PasswordVerificationOutcome.Success : PasswordVerificationOutcome.Failed;
        }
    }
}
