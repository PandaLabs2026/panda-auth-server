using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Persistence;
using PandaAuth.Shared;
using Xunit;

namespace PandaAuth.Tests;

public sealed class SeedPermissionPolicyTests
{
    [Fact]
    public void Default_Is_Additive_And_Exact_Allowlist_Is_Empty()
    {
        var options = new SeedOptions();
        Assert.Equal(SeedPermissionReconciliationMode.AddMissing, options.PermissionReconciliationMode);
        Assert.Empty(options.ExactPermissionClientIds);
        var plan = SeedPermissionPolicy.Plan(["old"], ["new"], options, FirstPartyClients.MeWeb);
        Assert.Empty(plan.Removed);
        Assert.Equal(new[] { "new", "old" }, plan.Target.Order());
    }

    [Fact]
    public void Exact_Only_Removes_For_An_Explicitly_Selected_Client()
    {
        var options = new SeedOptions { PermissionReconciliationMode = SeedPermissionReconciliationMode.Exact, ExactPermissionClientIds = [FirstPartyClients.MeWeb] };
        var selected = SeedPermissionPolicy.Plan(["old", "kept"], ["new", "kept"], options, FirstPartyClients.MeWeb);
        Assert.Equal(new[] { "old" }, selected.Removed);
        Assert.Equal(new[] { "kept", "new" }, selected.Target.Order());
        Assert.Empty(SeedPermissionPolicy.Plan(["old"], ["new"], options, FirstPartyClients.AdminWeb).Removed);
        Assert.Empty(SeedPermissionPolicy.Plan(selected.Target, ["new", "kept"], options, FirstPartyClients.MeWeb).Added);
        Assert.Empty(SeedPermissionPolicy.Plan(selected.Target, ["new", "kept"], options, FirstPartyClients.MeWeb).Removed);
    }

    [Theory]
    [InlineData("unknown-client")]
    [InlineData(FirstPartyClients.MeWeb)]
    public void Unknown_Or_Disabled_Allowlist_Fails(string clientId)
    {
        var options = new SeedOptions { ExactPermissionClientIds = [clientId] };
        options.Me.Enabled = false;
        Assert.Throws<InvalidOperationException>(() => SeedPermissionPolicy.Validate(options));
    }

    [Fact]
    public void Invalid_Mode_Fails()
        => Assert.Throws<InvalidOperationException>(() => SeedPermissionPolicy.Validate(new SeedOptions { PermissionReconciliationMode = (SeedPermissionReconciliationMode)999 }));

    [Fact]
    public async Task Configuration_Is_Checked_Before_Resolving_Writers()
    {
        var options = new AuthOptions();
        options.Seed.ExactPermissionClientIds = ["unknown-client"];
        using var provider = new ServiceCollection().AddSingleton(Options.Create(options)).BuildServiceProvider();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => DbSeeder.SeedAsync(provider));
        Assert.Contains("ExactPermissionClientIds", error.Message);
    }
}
