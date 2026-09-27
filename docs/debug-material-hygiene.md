# 调试材料与会话令牌卫生

报告问题时最常见的两类泄漏材料是浏览器 HAR 文件和命令行调试输出：它们会捕获**会话 Cookie、`Authorization: Bearer` 请求头和 `/connect/token` 响应体中的令牌**——这些材料被重放即可冒用对应身份（2023 年 Okta 支持通道事件的关键攻击链就是 HAR 中的会话令牌被重放）。本页说明哪些材料敏感、如何脱敏、以及服务端日志的默认行为边界。

## 一、哪些材料属于敏感

| 材料 | 携带的敏感内容 |
| --- | --- |
| 浏览器 HAR / devtools Network 导出 | IDP 会话 Cookie、me/admin 的会话 Cookie、API 调用的 `Authorization` 头、`/connect/token` 响应体中的 access/refresh token |
| `curl -v`、HTTP 代理调试输出 | 同上（含请求/响应头与体） |
| 反向代理访问日志 | `Authorization` 头（若记录了请求头）、含令牌的查询串 |
| 问题工单中的截图/粘贴文本 | 可能包含上述任何一项 |

会话 Cookie 与访问令牌等价：拿到任何一项都能在有效期内冒用会话，不要因为"只是 Cookie"而降低处理等级。

## 二、报告问题前的脱敏规则

1. 删除全部 `Cookie` 与 `Authorization` 请求头；
2. 删除 `/connect/token`、`/connect/userinfo`、`/connect/introspect` 等端点的请求/响应体（含 token 字段）；
3. 保留端点路径、状态码、错误码、时间序与请求 ID——定位问题通常足够；
4. 或者改用无痕窗口 + 专用测试账号复现问题，避免导出真实账号材料。

## 三、服务端日志的默认行为

- 三服务（server/admin/me）默认日志级别为 `Information`（`Microsoft.AspNetCore` 为 `Warning`）：2026-09-27 维护者审查未发现默认配置下任何日志调用记录令牌、Cookie 或凭据值，日志仅含结构化标识符（userId、clientId、路径、状态）。
- 请勿在生产把 `Microsoft.AspNetCore` 调到 `Debug`/`Trace`：OpenIddict 与 ASP.NET Core 在该级别可能输出协议请求内容。
- 管理审计（`admin_audit_logs`）与安全事件（`panda_security_events`）的设计约束为"密钥、令牌原文、Passkey 私钥不入审计字段"。
- 开发环境（`Environment.IsProduction() == false`）下，`DevEmailSender` 会把邮箱验证码写入日志以便联调；生产环境注册走 Resend 通道且缺配置启动即失败，验证码不会落日志。

## 四、边界

本页是使用指引，不是安全审计结论；上述"未发现"按三档制口径（审查时点证据）表述，不构成"永不泄漏"的保证。发现疑似令牌泄漏或安全问题请走 [SECURITY.md](../SECURITY.md) 的私密报告渠道。
