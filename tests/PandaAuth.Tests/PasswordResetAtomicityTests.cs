using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Features.Tokens;
using PandaAuth.Server.Infrastructure.Messaging;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PasswordResetAtomicityTests
{
    [PostgresFact]
    public async Task InvalidProof_AttemptPersists_AndMailFailureAfterCommitDoesNotRestoreProof()
    {
        var mail = new RecoveryMail { FailNotice = true };
        await using var fixture = await SecurityProtocolFixture.CreateAsync(services =>
        {
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(mail);
        });
        using (var setup = fixture.Host.Services.CreateScope())
            await setup.ServiceProvider.GetRequiredService<AccountVerificationService>().BeginPasswordResetAsync("security-admin@example.test");

        async Task<IActionResult> Reset(string token)
        {
            using var request = fixture.Host.Services.CreateScope();
            var controller = ActivatorUtilities.CreateInstance<CredentialController>(request.ServiceProvider);
            var http = new DefaultHttpContext { RequestServices = request.ServiceProvider };
            controller.ControllerContext = new ControllerContext(new ActionContext(http, new RouteData(), new ControllerActionDescriptor()));
            controller.TempData = new TempDataDictionary(http, new EmptyTempData());
            return await controller.ResetPassword(new ResetPasswordViewModel
            { Email = "security-admin@example.test", Token = token, NewPassword = "Changed!Password123" }, default);
        }
        Assert.IsType<ViewResult>(await Reset(new string('A', 43)));
        await using (var db = fixture.Context())
            Assert.Equal(1, (await db.PasswordResetRequests.SingleAsync()).Attempts);
        Assert.IsType<RedirectToActionResult>(await Reset(mail.Token!));
        Assert.IsType<ViewResult>(await Reset(mail.Token!));
        await using var verification = fixture.Context();
        Assert.NotNull((await verification.PasswordResetRequests.SingleAsync()).ConsumedAt);
        Assert.Equal(2, await verification.SecurityEvents.CountAsync());
        using var scope = fixture.Host.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        Assert.True(await users.CheckPasswordAsync((await users.FindByIdAsync(fixture.UserId))!, "Changed!Password123"));
    }

    [PostgresFact]
    public async Task RevocationFailure_RollsBackPasswordAndRecoveryTokenConsumption()
    {
        var mail = new RecoveryMail();
        await using var fixture = await SecurityProtocolFixture.CreateAsync(services =>
        {
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(mail);
            services.RemoveAll<ITokenRevoker>();
            services.AddScoped<ITokenRevoker, FailingRevoker>();
        });
        using (var setup = fixture.Host.Services.CreateScope())
        {
            await setup.ServiceProvider.GetRequiredService<AccountVerificationService>()
                .BeginPasswordResetAsync("security-admin@example.test");
        }
        Assert.NotNull(mail.Token);
        using (var request = fixture.Host.Services.CreateScope())
        {
            var controller = ActivatorUtilities.CreateInstance<CredentialController>(request.ServiceProvider);
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { RequestServices = request.ServiceProvider },
            };
            await Assert.ThrowsAsync<InjectedRevocationFailure>(() => controller.ResetPassword(new ResetPasswordViewModel
            {
                Email = "security-admin@example.test", Token = mail.Token!, NewPassword = "Changed!Password123",
            }, CancellationToken.None));
        }
        using var verification = fixture.Host.Services.CreateScope();
        var users = verification.ServiceProvider.GetRequiredService<UserService>();
        var user = await users.FindByIdAsync(fixture.UserId);
        Assert.NotNull(user);
        Assert.False(await users.CheckPasswordAsync(user, "Changed!Password123"));
        await using var db = fixture.Context();
        Assert.All(db.PasswordResetRequests.ToArray(), item => Assert.Null(item.ConsumedAt));
    }

    private sealed class InjectedRevocationFailure : Exception;
    private sealed class FailingRevoker : ITokenRevoker
    {
        public Task RevokeUserTokensAsync(string userId, string? clientId = null, CancellationToken cancellationToken = default)
            => throw new InjectedRevocationFailure();
        public Task RevokeClientTokensAsync(string clientId, CancellationToken cancellationToken = default)
            => throw new InjectedRevocationFailure();
    }
    private sealed class RecoveryMail : IEmailSender
    {
        public bool FailNotice { get; init; }
        public string? Token { get; private set; }
        public Task SendAsync(string email, string subject, string htmlBody, CancellationToken cancellationToken)
        {
            Token = Assert.Single(Regex.Matches(htmlBody, "[A-Za-z0-9_-]{43}").Select(match => match.Value));
            return Task.CompletedTask;
        }
        public Task SendPasswordResetNoticeAsync(string email, CancellationToken cancellationToken)
            => FailNotice ? Task.FromException(new InvalidOperationException("injected mail failure")) : Task.CompletedTask;
    }
    private sealed class EmptyTempData : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }
}
