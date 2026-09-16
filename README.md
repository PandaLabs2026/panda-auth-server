# panda-auth-server

**PandaAuth by PandaLabs** · [English](README.en.md)

> 研发阶段，尚无正式受支持发行版；接入采用邀请或申请口径。已有实现不等于已完成发行验证。

## 职责与边界

PandaAuth IDP 核心：ASP.NET Core Identity、EF Core/PostgreSQL 与 OpenIddict 7.7.0。持久化、迁移、登录控制器和服务测试归本仓；跨进程契约引用同级 [panda-auth-share](https://github.com/PandaLabs2026/panda-auth-share)。

## 当前实现与限制

- [协议注册](src/PandaAuth.Server/Program.cs)启用授权码配合 PKCE、客户端凭证和刷新令牌；配置 authorize/token/userinfo/logout/introspect/revoke 端点。
- [密码哈希](src/PandaAuth.Server/Infrastructure/Security/Argon2idPasswordHasher.cs)采用 Argon2id；[限流](src/PandaAuth.Server/Infrastructure/Security/LoginRateLimiter.cs)为内存 IP/账号双维固定窗口，条目按 TTL 回收；登录审计写入数据库，并由后台任务按默认 90 天的保留期清理（口径见[部署说明](deploy/README.md)）。
- [密钥存储](src/PandaAuth.Server/Infrastructure/Security/SigningKeyStore.cs)在启动时检查签名密钥轮换，不是运行中的定时轮换；加密密钥仅在缺失时创建。新旧密钥生效需要测试。
- [批量吊销服务](src/PandaAuth.Server/Features/Tokens/TokenRevocationService.cs)存在，尚未接入改密/冻结/注销流程。标准 revoke 处理单个提交的 token，不代表所有 API 或 Cookie 会话即时失效。
- [Web DemoClient](samples/PandaAuth.DemoClient)包含登录、profile、刷新、单 token 撤销和 RP 退出代码；[单元测试](tests/PandaAuth.Tests)覆盖哈希和限流，不是完整协议验证。

**静态核查发现启动阻断项：** `Program.cs` 调用 MapControllers 但缺少 MVC 服务注册；`--migrate` 分支调用 Seeder 时尚未注册其 OpenIddict 依赖。常驻启动先访问密钥表，Development 只播种，不自动迁移；Seed.Enabled 也尚未在 Seeder 中检查。当前不能将以下入口视为已验证 QuickStart。追踪见元仓 G00/G04/G07。

## 前置条件与构建运行

需要 .NET SDK，版本选择见本仓 [global.json](global.json)（当前请求 10.0.112，允许 latestFeature roll-forward）。七仓按[工作区布局](https://github.com/PandaLabs2026/panda-auth/blob/main/WORKSPACE.md)同级克隆，跨仓链接需要对应访问权限。以下命令在本仓根目录执行；本轮仅静态核对命令，未执行构建或启动。

需要同级 Share。运行需要独立的开发 PostgreSQL 数据库和对应权限；默认开发配置见 [appsettings.Development.json](src/PandaAuth.Server/appsettings.Development.json)。其中演示凭据仅用于隔离开发，不复制到生产或公开交付记录。

```bash
dotnet build PandaAuth.Server.slnx
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj
```

以下为源码已有入口及其用途，须先修复启动阻断并验证，不是当前可直接照抄的安装步骤：

| 命令 | 用途与副作用 |
| --- | --- |
| `dotnet run --project src/PandaAuth.Server -- --migrate` | 一次性迁移与种子入口；会修改数据库，当前种子依赖注册有缺口，失败不能推断数据库未改变 |
| `dotnet run --project src/PandaAuth.Server` | 常驻服务，开发监听 http://localhost:9004；结构需先准备 |
| `dotnet run --project samples/PandaAuth.DemoClient` | Web 示例，http://localhost:5201；需可用 IDP，通常在另一终端运行 |

协议路径：`/connect/authorize`、`/connect/token`、`/connect/userinfo`、`/connect/logout`、`/connect/introspect`、`/connect/revoke`；发现/JWKS 由 OpenIddict 提供，健康路径 `/healthz`。端点配置存在不等于启动或协议测试通过。

[部署说明](deploy/README.md)记录迁移约束和现有初始化限制。生产编排在元仓，不能用常驻启动代替一次性迁移。用户生命周期、验证码和管理 API 为 Phase 1 目标；Redis 和海外部署为后续目标。

## Roadmap 与治理

实现目标见[能力矩阵](https://github.com/PandaLabs2026/panda-auth/blob/main/docs/open-source/capabilities.md)与[发布门禁](https://github.com/PandaLabs2026/panda-auth/blob/main/docs/open-source/release-readiness.md)。实际业务需求驱动路线图，社区请求按方向和维护成本评估，不承诺交付。[社区/商业边界](https://github.com/PandaLabs2026/panda-auth/blob/main/docs/open-source/strategy.md)表示能力归属，不代表商业模块已经交付。

- [安全政策](SECURITY.md)：选定私密报告渠道，启用状态未核验；不公开提交漏洞细节。
- [贡献指南](CONTRIBUTING.md)：本仓检查与统一贡献规则。
- [MIT License](LICENSE)：适用于自有代码和文档，具体范围见[许可说明](LICENSING.md)；第三方许可仍适用，品牌图片除外。
