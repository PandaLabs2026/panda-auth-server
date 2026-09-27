using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace PandaAuth.Server.Features.Management;

/// <summary>
/// Management API 未启用时把管理控制器从路由模型整体摘除（清空 selectors），
/// 对外行为与「未注册」一致（路由 404），且不进 ApiExplorer。
/// 开关是部署面配置（Auth:Mgmt:Enabled），启动时一次性读取，运行期不热切换。
/// </summary>
internal sealed class MgmtRoutesDisabledConvention : IControllerModelConvention
{
    public void Apply(ControllerModel controller)
    {
        if (controller.ControllerType.Namespace?.StartsWith("PandaAuth.Server.Features.Management", StringComparison.Ordinal) == true)
        {
            controller.Selectors.Clear();
        }
    }
}
