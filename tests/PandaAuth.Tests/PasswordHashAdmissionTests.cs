using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using PandaAuth.Server.Configuration;
using PandaAuth.Server.Infrastructure.Security;
using Xunit;

namespace PandaAuth.Tests;

public sealed class PasswordHashAdmissionTests
{
    [Fact]
    public async Task Waiting_for_admission_does_not_block_the_request_thread()
    {
        using var budget = new PasswordHashWorkLimiter(new HttpContextAccessor());
        using var first = await budget.AcquireAsync(19456);
        using var second = await budget.AcquireAsync(19456);
        using var cancel = new CancellationTokenSource();
        IPasswordHasher hasher = new Argon2idPasswordHasher(budget);
        try
        {
            var invoked = Task.Run(() => new { Pending = hasher.HashAsync("synthetic-password", cancel.Token) });
            var call = await invoked.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.False(call.Pending.IsCompleted);
            cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call.Pending);
        }
        finally { cancel.Cancel(); }
    }

    [Fact]
    public void Enabled_host_cancels_hash_before_password_computation()
    {
        var services = new ServiceCollection();
        services.AddHttpContextAccessor();
        services.AddUserStore(PandaAuth.Server.Configuration.CookieSecurePolicy.Always, passwordWorkLimitEnabled: true);
        using var provider = services.BuildServiceProvider();
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        var accessor = provider.GetRequiredService<IHttpContextAccessor>();
        accessor.HttpContext = new DefaultHttpContext { RequestAborted = cancel.Token };
        using var scope = provider.CreateScope();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        Assert.ThrowsAny<OperationCanceledException>(() => hasher.Hash("synthetic-password"));
    }

    [Fact]
    public void Verification_cancellation_is_not_reported_as_a_wrong_password()
    {
        var original = new Argon2idPasswordHasher().Hash("synthetic-password");
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        var accessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext { RequestAborted = cancel.Token } };
        using var budget = new PasswordHashWorkLimiter(accessor);
        var hasher = new Argon2idPasswordHasher(budget);
        Assert.ThrowsAny<OperationCanceledException>(() => hasher.Verify(original, "synthetic-password"));
    }

    [Fact]
    public void Admission_preserves_argon2_strength_and_verification()
    {
        using var budget = new PasswordHashWorkLimiter(new HttpContextAccessor());
        var hasher = new Argon2idPasswordHasher(budget);
        var hash = hasher.Hash("synthetic-password");
        Assert.StartsWith("$argon2id$v=19$m=19456,t=2,p=1$", hash);
        Assert.Equal(PasswordVerificationOutcome.Success, hasher.Verify(hash, "synthetic-password"));
        Assert.Equal(PasswordVerificationOutcome.Failed, hasher.Verify(hash, "wrong-password"));
    }

    [Fact]
    public void Busy_is_retryable_and_does_not_expose_credentials()
    {
        var http = new DefaultHttpContext();
        var context = new ExceptionContext(new ActionContext(http, new RouteData(), new ActionDescriptor()), [])
        { Exception = new PasswordHashCapacityException() };
        context.Exception.Data["password"] = "synthetic-secret-never-return";
        new PasswordHashBusyExceptionFilter().OnException(context);
        Assert.True(context.ExceptionHandled);
        var result = Assert.IsType<ObjectResult>(context.Result);
        Assert.Equal(503, result.StatusCode);
        var problem = Assert.IsType<ProblemDetails>(result.Value);
        Assert.Equal("auth.service_busy", problem.Extensions["code"]);
        Assert.Null(problem.Detail);
        Assert.DoesNotContain("synthetic-secret-never-return", System.Text.Json.JsonSerializer.Serialize(problem));
        Assert.Equal("1", http.Response.Headers.RetryAfter);
        Assert.Equal("no-store", http.Response.Headers.CacheControl);
    }

    [Fact]
    public void Unrelated_exception_keeps_existing_handling()
    {
        var context = new ExceptionContext(new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor()), [])
        { Exception = new InvalidOperationException("unrelated") };
        new PasswordHashBusyExceptionFilter().OnException(context);
        Assert.False(context.ExceptionHandled);
        Assert.Null(context.Result);
    }
}
