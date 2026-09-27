# panda-auth-server 协作规则

## 职责与边界

本仓是 PandaAuth IDP 核心服务，负责 OpenIddict 端点、登录、持久化、审计、密钥轮换、EF 迁移及 Server 测试；生产监听 `127.0.0.1:6000`。跨仓发布、数据库角色、备份和 Caddy 以 `../panda-auth/AGENTS.md`、`../panda-auth/WORKSPACE.md`、`../panda-auth/deploy/README.md` 为准。

## 跨仓来源与安全

- 共享端点/Claim 使用同级 `../panda-auth-share/`，不得复制契约字面量；生产部署事实以元仓部署文档为准。
- 运行服务不得在启动时隐式执行迁移。结构变更通过一次性 migrator；生产迁移前必须备份并验证可恢复，遵循元仓发布门禁。
- 不提交密码、Token、签名私钥、真实生产连接串、env 内容或生产配置；Demo 凭据仅限隔离开发环境。
- 不手工编辑构建生成物；迁移由 EF 工具按本仓实体与模型快照生成并审查。

## 验证与 PostgreSQL 条件

从本仓根目录运行：

```bash
dotnet build PandaAuth.Server.slnx --no-restore
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj --no-restore
git diff --check
```

构建和不依赖数据库的单元测试可独立运行。完整数据库测试需要专用、可丢弃的隔离 PostgreSQL，并通过环境变量 `PANDA_AUTH_TEST_POSTGRES` 提供测试连接串，例如 `PANDA_AUTH_TEST_POSTGRES='Host=127.0.0.1;Port=5432;Database=panda_auth_test;Username=...;Password=...'`；不得连接生产数据库或复用生产凭据。未设置变量时，`PostgresFact` 用例会以缺少隔离连接为由跳过；这不是通过。测试报告必须分别给出 passed、failed、skipped 数量及跳过原因。

仅在本次明确启用数据库测试且使用临时/批准的隔离实例时才启动数据库。结束后只清理由本次创建的测试容器、测试数据库和临时文件，并记录清理结果；不得做无范围 Docker 清理。完整验证按本任务要求使用 `--no-restore`；依赖未还原导致命令无法运行时，明确报告未完成，不连接生产服务补救。
