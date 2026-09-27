using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace PandaAuth.Server.Features.Management;

/// <summary>
/// Management API 未启用时把管理控制器从应用模型整体移除——路由不存在（对外 404）且不进 ApiExplorer。
/// 注意不能清空 controller.Selectors：那会让动作退化为「conventional routing」，
/// 触发 ApiExplorer 的启动期异常（ApiController 动作必须 attribute routing）。
/// 开关是部署面配置（Auth:Mgmt:Enabled），启动时一次性读取，运行期不热切换。
/// </summary>
internal sealed class MgmtRoutesDisabledConvention : IApplicationModelConvention
{
    public void Apply(ApplicationModel application)
    {
        for (var index = application.Controllers.Count - 1; index >= 0; index--)
        {
            var controller = application.Controllers[index];
            if (controller.ControllerType.Namespace?.StartsWith("PandaAuth.Server.Features.Management", StringComparison.Ordinal) == true)
            {
                application.Controllers.RemoveAt(index);
            }
        }
    }
}
