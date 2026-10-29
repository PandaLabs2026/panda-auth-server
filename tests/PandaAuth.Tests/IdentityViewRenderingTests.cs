using Microsoft.AspNetCore.TestHost;
using PandaAuth.Server.IdentityViewTests;
using Xunit;
namespace PandaAuth.Tests;

public sealed class IdentityViewRenderingTests
{
    [Theory]
    [InlineData("login")]
    [InlineData("challenge")]
    [InlineData("recovery")]
    [InlineData("blocked")]
    [InlineData("mfa-enroll")]
    [InlineData("mfa-assert")]
    [InlineData("forgot")]
    [InlineData("reset")]
    [InlineData("change-password")]
    [InlineData("confirm-email")]
    [InlineData("change-email")]
    [InlineData("confirm-email-change")]
    public async Task ActualIdentityViews_RenderOneLightResponsiveHeading_WithoutChangingForms(string page)
    {
        await using var app = IdentityPreview.Build(RepositoryRoot(), host => host.UseTestServer());
        await app.StartAsync();
        using var client = app.GetTestClient();
        var response = await client.GetAsync("/fixture/" + page);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("aria-labelledby=\"identity-title\"", html);
        Assert.Equal(1, html.Split("<h1").Length - 1);
        Assert.Contains("/account/brand/pandaauth-logo-horizontal.png", html);
        Assert.Contains("100svh", html);
        Assert.DoesNotContain("Phase 0", html);
        if (page is not "blocked") Assert.Contains("__RequestVerificationToken", html);
        if (page is not "blocked" and not "confirm-email") Assert.Contains("/me/security?tab=totp", html);
    }

    [Fact]
    public async Task InvalidLogin_AnnouncesAndFocusesTheError_WithoutLeakingDraftPassword()
    {
        await using var app = IdentityPreview.Build(RepositoryRoot(), host => host.UseTestServer());
        await app.StartAsync();
        using var client = app.GetTestClient();
        var html = await client.GetStringAsync("/fixture/login-error");
        Assert.Contains("role=\"alert\"", html);
        Assert.Contains("tabindex=\"-1\" autofocus=\"autofocus\"", html);
        Assert.Contains("validation-summary-errors", html);
        Assert.Contains("autocomplete=\"current-password\"", html);
    }

    [Fact]
    public async Task Preview_CannotExecuteProductionActions_ButPreservesActualFormTargets()
    {
        await using var app = IdentityPreview.Build(RepositoryRoot(), host => host.UseTestServer());
        await app.StartAsync();
        using var client = app.GetTestClient();
        var html = await client.GetStringAsync("/fixture/login");
        Assert.Contains("action=\"/account/login\"", html);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, (await client.PostAsync("/account/login", new StringContent(""))).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, (await client.GetAsync("/connect/authorize")).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.OK, (await client.GetAsync("/account/mfa.js")).StatusCode);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PandaAuth.Server.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Server source root missing");
    }
}
