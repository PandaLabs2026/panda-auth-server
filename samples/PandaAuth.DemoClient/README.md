# 本机 Web 登录示例

本目录展示 ASP.NET Core / OpenIddict 客户端的授权码＋PKCE、刷新、撤销和 RP 登出流程。[协议 SDK 与 M2M 示例](../../../panda-auth-sdk/README.md)由同级 SDK 仓维护。

从 Server 仓根运行：

```sh
dotnet run --project samples/PandaAuth.DemoClient
```

启动配置使用 Development 和 `http://localhost:5201/`。通过 `Auth:Issuer` 配置所选真实测试 IDP；不要把客户端机密写入示例。IDP 应预先登记公共客户端 `demo-public`，精确回调为 `http://localhost:5201/callback/login/pandaauth`，登出返回为 `http://localhost:5201/`，并允许所需授权码、PKCE、刷新、撤销、登出及身份 scopes。

示例使用临时 state 签名/加密密钥，不依赖 OpenIddict 数据库存储；重启会使尚未完成的登录 state 失效。HTTP 传输例外仅在 Development 启用，非开发环境仍要求 HTTPS。

access/refresh token 仅保存在 DataProtection 保护的认证票据中；Profile 只显示身份字段和令牌存在与否，不展示令牌值。这个本机单进程示例不代表生产 BFF、持久化凭据、会话治理或多实例部署方案。
