using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using PandaAuth.Server.Features.Admin;
using Xunit;

namespace PandaAuth.Tests;

public class AdminErrorCodeFilterTests
{
    private static (ActionExecutedContext Context, ObjectResult Result) Exec(ProblemDetails problem)
    {
        var result = new ObjectResult(problem);
        var context = new ActionExecutedContext(
            new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor()),
            new List<IFilterMetadata>(),
            new object())
        {
            Result = result,
        };
        new AdminErrorCodeFilter().OnActionExecuted(context);
        return (context, result);
    }

    [Fact]
    public void Registered_Title_Gets_Stable_Code()
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status400BadRequest,
            Title = "不能重置自己的密码",
            Detail = "管理端重置会强制下线目标账号的全部会话（包括你当前的管理台会话）。修改自己的密码请使用自助改密流程。",
        };

        Exec(problem);

        Assert.Equal("user.self_password_reset_forbidden", problem.Extensions["code"]);
    }

    [Fact]
    public void Unregistered_Title_Stays_Codeless()
    {
        var problem = new ProblemDetails { Status = 400, Title = "某个动态 title", Detail = "细节" };

        Exec(problem);

        Assert.False(problem.Extensions.ContainsKey("code"));
    }

    [Fact]
    public void Existing_Code_Is_Not_Overwritten()
    {
        var problem = new ProblemDetails { Status = 400, Title = "账号已注销" };
        problem.Extensions["code"] = "custom.already_here";

        Exec(problem);

        Assert.Equal("custom.already_here", problem.Extensions["code"]);
    }

    [Fact]
    public void All_Registered_Codes_Are_Dot_Namespaced()
    {
        // 前端按 t('server.' + code) 查找：码必须是点分命名空间形态且整体为小写 DNS 安全串。
        foreach (var (_, code) in AdminErrorCodeFilter.CodeByTitle)
        {
            Assert.Matches(@"^[a-z]+(\.[a-z_]+)+$", code);
        }
    }

    [Fact]
    public void Registry_Titles_Are_Unique()
    {
        // 字典初始化器对重复 key 会抛——此断言是防「改回可重复集合」的锁线。
        Assert.Equal(AdminErrorCodeFilter.CodeByTitle.Count,
            AdminErrorCodeFilter.CodeByTitle.Values.Distinct().Count());
    }
}
