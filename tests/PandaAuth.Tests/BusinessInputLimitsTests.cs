using PandaAuth.Server.Features.Account;
using PandaAuth.Server.Features.Admin;
using PandaAuth.Server.Features.Management;
using PandaAuth.Server.Infrastructure.Security;
using PandaAuth.Shared;
using Xunit;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;

namespace PandaAuth.Tests;

public sealed class BusinessInputLimitsTests
{
    [Theory]
    [InlineData(2349)]
    [InlineData(8192)]
    public void Oidc_ReturnUrl_Uses_A_Separate_Bounded_Limit(int length)
    {
        var returnUrl = "/connect/authorize?state=".PadRight(length, 'x');
        Assert.Empty(BusinessInputLimits.Validate("returnUrl", returnUrl));
        foreach (var model in ReturnUrlModels(returnUrl))
            Assert.Empty(BusinessInputLimits.Validate("model", model));
    }

    [Fact]
    public void Oversized_ReturnUrl_Is_Rejected_On_Get_And_All_Account_Forms()
    {
        var returnUrl = "/" + new string('x', 8192);
        Assert.Contains("returnUrl", BusinessInputLimits.Validate("returnUrl", returnUrl));
        foreach (var model in ReturnUrlModels(returnUrl))
            Assert.Contains("ReturnUrl", BusinessInputLimits.Validate("model", model));
        Assert.Contains("RedirectUris", BusinessInputLimits.Validate("request",
            new AdminRedirectUrisRequest(["https://example.test/".PadRight(2049, 'x')], [])));
    }

    [Fact]
    public void Html_Login_Filter_Preserves_Normal_Oidc_Context_Without_ModelState_Error()
    {
        var returnUrl = "/connect/authorize?client_id=admin-web&state=" + new string('x', 2400);
        foreach (var model in new object[] { returnUrl, new LoginViewModel { UserName = "fixture", ReturnUrl = returnUrl } })
        {
            var context = Context(System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(AccountController)));
            context.ActionArguments[model is string ? "returnUrl" : "model"] = model;
            new BusinessInputLimitFilter().OnActionExecuting(context);
            Assert.True(context.ModelState.IsValid);
            Assert.Null(context.Result);
        }
    }

    private static object[] ReturnUrlModels(string returnUrl) =>
    [
        new LoginViewModel { UserName = "fixture", ReturnUrl = returnUrl },
        new ForgotPasswordViewModel { ReturnUrl = returnUrl },
        new ResetPasswordViewModel { ReturnUrl = returnUrl },
        new ChangePasswordViewModel { ReturnUrl = returnUrl },
        new ChangeEmailViewModel { ReturnUrl = returnUrl },
        new ConfirmEmailChangeViewModel { ReturnUrl = returnUrl }
    ];

    [Theory]
    [InlineData("query", 256)]
    [InlineData("userId", 450)]
    [InlineData("id", 450)]
    [InlineData("roleId", 450)]
    [InlineData("clientId", 100)]
    public void Route_And_Search_Boundaries(string name, int maximum)
    {
        Assert.Empty(BusinessInputLimits.Validate(name, new string('x', maximum)));
        Assert.NotEmpty(BusinessInputLimits.Validate(name, new string('x', maximum + 1)));
    }

    [Fact]
    public void New_Password_Is_Bounded_Without_Changing_Historical_Verification()
    {
        var password = new string(' ', 1024);
        Assert.Empty(BusinessInputLimits.Validate("request", new AdminResetPasswordRequest(password)));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminResetPasswordRequest(password + "x")));
        Assert.Empty(BusinessInputLimits.Validate("model", new LoginViewModel { UserName = "user", Password = new string('x', 2048) }));
        Assert.Empty(BusinessInputLimits.Validate("model", new ChangePasswordViewModel { CurrentPassword = new string('x', 2048), NewPassword = password }));
    }

    [Fact]
    public void Claim_And_Profile_Fields_Are_Bounded()
    {
        Assert.Empty(BusinessInputLimits.Validate("request", new AdminClaimRequest(new string('x', 128), new string('x', 2048), new string('x', 128))));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminClaimRequest("panda:x", new string('x', 2049), "profile")));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminUserProfileRequest("a@b.test", new string('x', 129), null)));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminUserProfileRequest(null, null, new string('x', 65))));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminCreateUserRequest(new string('x', 257), null, null, null, null, false)));
        Assert.NotEmpty(BusinessInputLimits.Validate("query", new string('\u0344', 256)));
    }

    [Fact]
    public void Lists_Are_Bounded_Before_Uri_Parsing_And_Permission_Processing()
    {
        Assert.Empty(BusinessInputLimits.Validate("request", new AdminRedirectUrisRequest(Enumerable.Repeat("https://example.test", 32).ToArray(), [])));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminRedirectUrisRequest(Enumerable.Repeat("https://example.test", 33).ToArray(), [])));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminRedirectUrisRequest([new string('x', 2049)], [])));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminPermissionsRequest(Enumerable.Repeat("x", 129).ToArray())));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new AdminUserRolesRequest([new string('x', 257)])));
        Assert.NotEmpty(BusinessInputLimits.Validate("request", new ManagementCreateClientRequest(new string('x', 257), null, null, null, null)));
    }

    [Fact]
    public void Filter_Short_Circuits_Json_Before_Action_And_Does_Not_Expose_Input()
    {
        var context = Context(new AdminRolesController(null!));
        context.ActionArguments["query"] = new string('s', 257);
        new BusinessInputLimitFilter().OnActionExecuting(context);
        var result = Assert.IsType<BadRequestObjectResult>(context.Result);
        var problem = Assert.IsType<ValidationProblemDetails>(result.Value);
        Assert.Equal(400, problem.Status);
        Assert.Contains("query", problem.Errors.Keys);
        Assert.DoesNotContain(new string('s', 257), string.Join("", problem.Errors.Values.SelectMany(x => x)));
    }

    [Fact]
    public void Html_Uses_ModelState_And_Unowned_Actions_Are_Untouched()
    {
        // The filter only inspects controller type; no controller dependencies run.
        var html = Context(System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(AccountController)));
        html.ActionArguments["model"] = new LoginViewModel { UserName = new string('x', 257) };
        new BusinessInputLimitFilter().OnActionExecuting(html);
        Assert.Null(html.Result);
        Assert.False(html.ModelState.IsValid);
        var unowned = Context(new object());
        unowned.ActionArguments["query"] = new string('x', 257);
        new BusinessInputLimitFilter().OnActionExecuting(unowned);
        Assert.True(unowned.ModelState.IsValid);
        Assert.Null(unowned.Result);
    }

    private static ActionExecutingContext Context(object controller) => new(
        new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor()),
        new List<IFilterMetadata>(), new Dictionary<string, object?>(), controller);
}
