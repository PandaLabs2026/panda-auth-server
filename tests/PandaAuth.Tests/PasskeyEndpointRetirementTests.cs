using System.Net;
using System.Net.Http;
using Xunit;

namespace PandaAuth.Tests;

/// <summary>
/// 旧端点退出行为守护（AUTH-DELIVERY-002，任务书 §五「旧端点退出」）：
/// Passkey 注册/断言端点必须从路由模型中消失（404），而不是仅被门禁挡住——
/// 404 说明产品入口已删除；若将来出现 302/400（cookie 跳登录或防伪拒绝）即意味着
/// 端点被悄悄恢复了，本测试红。
/// </summary>
public class PasskeyEndpointRetirementTests
{
    private static readonly string[] RetiredEndpoints =
    [
        // me 自助域（/account/mfa/user/passkey/*）
        "/account/mfa/user/passkey/enrollment/options",
        "/account/mfa/user/passkey/enrollment/complete",
        "/account/mfa/user/passkey/assertion/options",
        "/account/mfa/user/passkey/assertion/complete",
        // 管理员安全验证页（/account/mfa/{enrollment,assertion}/*）
        "/account/mfa/enrollment/options",
        "/account/mfa/enrollment/complete",
        "/account/mfa/assertion/options",
        "/account/mfa/assertion/complete",
        // 登录挑战页（/account/mfa/challenge/passkey/*）
        "/account/mfa/challenge/passkey/options",
        "/account/mfa/challenge/passkey/complete",
    ];

    [PostgresFact]
    public async Task RetiredPasskeyEndpoints_AreGoneFromRouting_NotMerelyForbidden()
    {
        await using var fixture = await SecurityProtocolFixture.CreateAsync();
        using var browser = fixture.Browser();

        foreach (var endpoint in RetiredEndpoints)
        {
            using var response = await browser.PostAsync(endpoint, new FormUrlEncodedContent([]));
            Assert.True(HttpStatusCode.NotFound == response.StatusCode,
                $"{endpoint} 应已退出路由（404），实际 {response.StatusCode}——端点可能被恢复。");
        }
    }
}
