using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>Capacity exhaustion is retryable and must not be reported as invalid credentials.</summary>
public sealed class PasswordHashBusyExceptionFilter : IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        if (context.Exception is not PasswordHashCapacityException || context.HttpContext.Response.HasStarted)
            return;

        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status503ServiceUnavailable,
            Title = "Authentication service busy",
        };
        problem.Extensions["code"] = "auth.service_busy";
        context.HttpContext.Response.Headers.RetryAfter = "1";
        context.HttpContext.Response.Headers.CacheControl = "no-store";
        context.Result = new ObjectResult(problem) { StatusCode = problem.Status };
        context.ExceptionHandled = true;
    }
}
