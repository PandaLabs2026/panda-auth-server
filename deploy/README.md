# PandaAuth.Server 部署与开发说明

生产编排在[元仓部署指南](https://github.com/PandaLabs2026/panda-auth/blob/main/deploy/README.md)，本目录只保存 Server 专属脚本和迁移说明。

> 当前启动与迁移入口存在静态阻断项，见[能力矩阵](https://github.com/PandaLabs2026/panda-auth/blob/main/docs/open-source/capabilities.md)的 G00。以下说明源码入口与目标流程，不代表已经验证可部署；本轮没有运行数据库命令。

## 数据库与权限

运行依赖 PostgreSQL，开发配置见 [appsettings.Development.json](../src/PandaAuth.Server/appsettings.Development.json)，使用独立开发库。不要让开发配置指向生产，也不要将演示凭据用于生产。

[setup-databases.sh](setup-databases.sh)面向宿主机已有 PostgreSQL 容器，会创建角色/数据库并授予运行角色 public schema 的 CREATE/ALL。当前脚本与“不为运行账号扩大迁移 DDL 权限”的治理目标不一致，尚未整改；不能把它作为已经落实最小权限的通用安装步骤。权限分离与恢复演练跟踪在 G08。

## 迁移与启动

`dotnet run --project src/PandaAuth.Server -- --migrate` 是本仓根目录的一次性入口，会执行 EF 迁移并调用种子逻辑。当前分支在注册 OpenIddict 前调用依赖其 ApplicationManager 的 Seeder，需要先修复；命令失败也可能已经修改数据库。

常驻命令 `dotnet run --project src/PandaAuth.Server` 在启动前读取密钥表。Development 仅执行种子逻辑，不自动迁移。不得把新数据库直接正常启动当成初始化流程；Seed.Enabled 开关目前也未在 Seeder 中检查。

生产一次性迁移的固定命令（只在修复、备份和独立恢复验证完成后，在服务器 `~/app/panda-auth/deploy` 使用）：

```bash
docker compose -p panda-auth --env-file .env --env-file ~/.config/panda-auth/panda-auth.env run --rm auth-server --migrate
```

结构变化前用 `pg_dump -Fc` 备份到 `~/app/panda-auth/backups/pre-<变更>-<UTC时间戳>.dump`，并在临时 postgres:18 容器验证可恢复；不得覆盖生产数据库。通过一次性迁移执行结构变化，不依赖常驻服务启动迁移，不为运行角色扩大 DDL 权限。

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
