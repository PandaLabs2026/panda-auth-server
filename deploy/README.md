# PandaAuth.Server 部署与开发说明

生产编排在[元仓部署指南](https://github.com/PandaLabs2026/panda-auth/blob/main/deploy/README.md)，本目录只保存 Server 专属脚本和迁移说明。

> MVC 注册、迁移时 OpenIddict Core 注册、Seed.Enabled 语义和首次签名密钥装配已修复，并在临时 PostgreSQL 18 上验证空库迁移、运行账号启动、健康检查和登录视图。生产数据库与发布仍未配置完成。

## 数据库与权限

运行依赖 PostgreSQL，开发配置见 [appsettings.Development.json](../src/PandaAuth.Server/appsettings.Development.json)，使用独立开发库。不要让开发配置指向生产，也不要将演示凭据用于生产。

[setup-databases.sh](setup-databases.sh)面向宿主机 PostgreSQL 18，由管理员执行。脚本创建独立 `panda_auth`（运行）与 `panda_auth_migrator`（迁移）角色；数据库由 migrator 所有，运行角色只有 DML 权限。通过 `\password` 交互设置密码，并为本机回环连接增加 SCRAM 规则。服务器密钥文件保存 `DB_PASSWORD`、`DB_MIGRATOR_PASSWORD` 等值；不要将它们提交到仓库。

## 迁移与启动

`dotnet run --project src/PandaAuth.Server -- --migrate` 是本仓根目录的一次性入口，使用 `ConnectionStrings:Migration` 执行 EF 迁移并调用 OpenIddict 种子逻辑；常驻服务仅使用 `ConnectionStrings:Default`。`Auth:Seed:Enabled=false` 会跳过全部种子数据。创建 `me-web` 时必须注入 `Auth:Seed:MeClientSecret`。

常驻命令 `dotnet run --project src/PandaAuth.Server` 仅使用 `ConnectionStrings:Default` 并在启动前读取密钥表。Development 可执行种子逻辑，不自动迁移；`Seed.Enabled=false` 会跳过整个 Seeder。不得把新数据库直接正常启动当成初始化流程。

生产一次性迁移的固定命令（只在修复、备份和独立恢复验证完成后，在服务器 `~/app/panda-auth/deploy` 使用）：

```bash
docker compose -p panda-auth --env-file .env --env-file ~/.config/panda-auth/panda-auth.env --profile migrate run --rm auth-server-migrate
```

结构变化前用 `pg_dump -Fc` 备份到 `~/app/panda-auth/backups/pre-<变更>-<UTC时间戳>.dump`，并在临时 postgres:18 容器验证可恢复；不得覆盖生产数据库。通过一次性迁移账号执行结构变化，不依赖常驻服务启动迁移，不为运行角色扩大 DDL 权限。

## 开发构建与验证

按本仓 global.json 准备 .NET SDK，Share 必须同级克隆。以下从本仓根目录执行：

```bash
dotnet build PandaAuth.Server.slnx
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj
```

EF 工具版本在 [.config/dotnet-tools.json](../.config/dotnet-tools.json)。需要开发新迁移时先 `dotnet tool restore`，再使用本仓的设计时工厂；新增迁移属于服务开发任务，不是本文档治理的验证步骤。

修复启动问题后，开发服务入口为 http://localhost:9004，DemoClient 为 http://localhost:5201。端到端验证需要单独完成。

## 镜像

Server 的 Dockerfile 需要工作区根上下文，以包含同级 Share；正式发布唯一通道为元仓 release.sh。其 dry-run 仍执行本地构建，不用于文档验证。镜像、数据库、Caddy 与探活按元仓指南协调，不通过手工 push 或 scp 绕过发布通道。
