# panda-auth-server 协作规则

PandaAuth IDP 核心服务，生产监听 127.0.0.1:6000。跨仓发布、迁移角色、备份和 Caddy 规则以 `../panda-auth/AGENTS.md`、`WORKSPACE.md` 和 `deploy/README.md` 为准。

- 业务持久化、OpenIddict、登录控制器、审计、密钥轮换和 EF 迁移归本仓；共享端点/Claim 使用同级 `../panda-auth-share/`，不得复制契约字面量。
- 运行服务不在启动时隐式执行迁移；结构变更使用一次性 migrator，迁移前必须备份并验证可恢复，禁止把生产凭据写入仓库、日志或命令历史。
- 不提交密码、Token、签名私钥、env 内容或真实生产连接串；Demo 凭据只用于隔离开发。
- 验证：`dotnet build PandaAuth.Server.slnx`、`dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj` 和 `git diff --check`。
