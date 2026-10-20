using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Features.Management;

namespace PandaAuth.Server.Infrastructure.Security;

/// <summary>Only owned business actions; protocol and WebAuthn payloads keep their own limits.</summary>
public sealed class BusinessInputLimitFilter : IActionFilter
{
    public void OnActionExecuting(ActionExecutingContext context)
    {
        var controller = context.Controller;
        var html = controller is AccountController or CredentialController;
        if (!html && controller is not (AdminUsersController or AdminRolesController or
            AdminClaimsController or AdminClientsController or AdminAuditController or
            ManagementUsersController or ManagementClientsController)) return;

        var exceeded = false;
        foreach (var (name, value) in context.ActionArguments)
            foreach (var field in BusinessInputLimits.Validate(name, value))
            {
                exceeded = true;
                context.ModelState.AddModelError(field, "输入超出允许长度或数量。");
            }

        // Existing HTML actions render their form with ModelState errors.
        if (!html && exceeded)
            context.Result = new BadRequestObjectResult(new ValidationProblemDetails(context.ModelState)
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "输入超出允许长度或数量",
            });
    }

    public void OnActionExecuted(ActionExecutedContext context) { }
}
