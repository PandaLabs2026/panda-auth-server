using System.Reflection;
using OpenIddict.Abstractions;
using PandaAuth.Server.Infrastructure.Persistence;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PandaAuth.Tests;

public class PandaMadeRegistrationTests
{
    [Fact]
    public void AdminAndIntrospectionDescriptorsHaveDistinctMinimalPermissions()
    {
        var type = typeof(PandaAuthDbContext).Assembly.GetType("PandaAuth.Server.Features.PandaMade.PandaMadeRegistration");
        Assert.NotNull(type);
        var describe = type.GetMethod("Describe", BindingFlags.Static | BindingFlags.Public)!;
        var result = ((OpenIddictScopeDescriptor Scope, OpenIddictApplicationDescriptor Admin, OpenIddictApplicationDescriptor Api))describe.Invoke(null, [new Uri("https://localhost:6501/"), new string('a', 40), new string('b', 40)])!;
        Assert.Equal("pandamade.manage", result.Scope.Name);
        Assert.Equal(new[] { "pandamade-api" }, result.Scope.Resources);
        Assert.Equal("pandamade-admin", result.Admin.ClientId);
        Assert.Equal(new[] { new Uri("https://localhost:6501/signin-oidc") }, result.Admin.RedirectUris);
        Assert.Equal(new[] { new Uri("https://localhost:6501/signout-callback-oidc") }, result.Admin.PostLogoutRedirectUris);
        Assert.Contains(Requirements.Features.ProofKeyForCodeExchange, result.Admin.Requirements);
        Assert.Contains(Permissions.GrantTypes.AuthorizationCode, result.Admin.Permissions);
        Assert.Contains(Permissions.GrantTypes.RefreshToken, result.Admin.Permissions);
        Assert.DoesNotContain(Permissions.GrantTypes.ClientCredentials, result.Admin.Permissions);
        Assert.Equal(ClientTypes.Confidential, result.Api.ClientType);
        Assert.Equal(new[] { Permissions.Endpoints.Introspection }, result.Api.Permissions);
        Assert.Empty(result.Api.RedirectUris);
    }

    [Fact]
    public async Task RetiredRegistrationCliStaysFailClosed()
    {
        // ADR-089 批次 3：--register-pandamade-clients 已退役为显式拒绝，
        // 不得落入正常启动（不监听 HTTP、不读库、退出码 1）。
        var executable = Path.GetFullPath("../../../../../src/PandaAuth.Server/bin/Debug/net10.0/PandaAuth.Server.dll", AppContext.BaseDirectory);
        var start = new System.Diagnostics.ProcessStartInfo("dotnet", executable + " --register-pandamade-clients") { RedirectStandardOutput = true, RedirectStandardError = true };
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        start.Environment.Remove("ConnectionStrings__Default");
        using var process = System.Diagnostics.Process.Start(start)!;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var stderr = await process.StandardError.ReadToEndAsync(deadline.Token);
        var stdout = await process.StandardOutput.ReadToEndAsync(deadline.Token);
        await process.WaitForExitAsync(deadline.Token);
        Assert.Equal(1, process.ExitCode);
        Assert.Equal("pandamade-registration-closed\n", stderr.Replace("\r\n", "\n"));
        Assert.DoesNotContain("Now listening on", stdout);
        Assert.Empty(stdout);
    }

    [Theory]
    [InlineData("http://localhost:6501/")]
    [InlineData("https://localhost:6501/admin/")]
    [InlineData("https://localhost:6501/?query=1")]
    [InlineData("https://user:pass@localhost:6501/")]
    public void CallbackOriginMustBeExactHttpsRoot(string origin)
    {
        var type = typeof(PandaAuthDbContext).Assembly.GetType("PandaAuth.Server.Features.PandaMade.PandaMadeRegistration");
        Assert.NotNull(type);
        var failure = Assert.Throws<TargetInvocationException>(() => type.GetMethod("Describe")!.Invoke(null, [new Uri(origin), new string('a', 40), new string('b', 40)]));
        Assert.IsType<InvalidOperationException>(failure.InnerException);
    }
}
