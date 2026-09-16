# PandaAuth.Server 部署与开发说明

生产编排在[元仓部署指南](https://github.com/PandaLabs2026/panda-auth/blob/main/deploy/README.md)，本目录只保存 Server 专属脚本和迁移说明。

> MVC 注册、迁移时 OpenIddict Core 注册、Seed.Enabled 语义和首次签名密钥装配已修复，并在临时 PostgreSQL 18 上验证空库迁移、运行账号启动、健康检查和登录视图。生产数据库与发布仍未配置完成。

## 数据库与权限

运行依赖 PostgreSQL，开发配置见 [appsettings.Development.json](../src/PandaAuth.Server/appsettings.Development.json)，使用独立开发库。不要让开发配置指向生产，也不要将演示凭据用于生产。

[setup-databases.sh](setup-databases.sh)面向宿主机 PostgreSQL 18，由管理员执行。脚本创建独立 `panda_auth`（运行）与 `panda_auth_migrator`（迁移）角色；数据库由 migrator 所有，运行角色只有 DML 权限。通过 `\password` 交互设置密码，并为本机回环连接增加 SCRAM 规则。服务器密钥文件保存 `DB_PASSWORD`、`DB_MIGRATOR_PASSWORD` 等值；不要将它们提交到仓库。

脚本不绑定具体账号与个人路径，默认规则（均可覆盖）见脚本头注释：运行账号默认取 `SUDO_USER`（`PANDA_AUTH_RUN_USER` 可覆盖），密钥文件默认取该账号家目录下的 `.config/panda-auth/panda-auth.env`（`PANDA_AUTH_SECRET_FILE` 可覆盖），并要求该文件属于该账号且权限为 0600。

运行角色对 `signing_keys` 只有 `SELECT/INSERT/UPDATE`，**无 `DELETE`**：代码（`Infrastructure/Security/SigningKeyStore.cs`）只新增密钥、把超期密钥置 `Retired`，从无删除路径，收紧后可消除「运行账号被攻陷即抹除密钥历史」的破坏面。

⚠️ **首次装机要跑两次本脚本**，顺序是：跑本脚本（建角色/库）→ 跑一次性迁移（建表）→ **再跑一次本脚本**（收紧 `signing_keys` 的 `DELETE`）。原因：`ALTER DEFAULT PRIVILEGES` 只作用于此后新建的表，而首次装机时 `signing_keys` 还不存在，第一次运行时 `REVOKE` 是空操作。脚本在这种状态下不会静默通过——结束时会在 stderr 明确打印「未完成：signing_keys 尚不存在…迁移完成后请重跑本脚本」；表存在且权限已收紧时打印「已收紧并自检通过」；表存在但仍带 `DELETE` 时直接非零退出。已迁移的生产库重跑一次即生效。

`signing_keys` 若被重建（例如迁移中 drop/create）同样会重新带上 `DELETE`（默认权限所致），需再重跑本脚本；本脚本幂等，可反复执行。

## 登录审计日志保留

每次登录尝试（含失败）都会同步写一行 `login_logs`，该表无分区，因此有明确的保留口径：

- 保留期由 `Auth:Audit:RetentionDays` 配置，默认 **90 天**（生产可在 `.env` 用 `Auth__Audit__RetentionDays` 覆盖）；
- 清理由常驻服务内的后台任务执行（`Infrastructure/Security/LoginLogRetentionService.cs`）：进程启动后立即清理一次，此后每 24 小时一次，删除 `CreatedAt` 早于「当前时间 − 保留天数」的记录，每批 500 行，避免长事务与长时间持锁；
- 启动时会打印一条 info 日志说明该口径（保留天数、周期、批大小）；单次失败只记录错误并在下一周期重试，不会让清理任务退出；
- `RetentionDays ≤ 0` 视为误配：任务拒绝执行并打印 warning（避免把「删光全部审计」当成合法配置）。

查询当前保留口径：`docker compose -p panda-auth logs auth-server | grep 登录审计日志保留策略`。

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
