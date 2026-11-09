# Auth → Oasis 隔离联通

这是按需运行的跨拥有方测试项目，不加入普通 Server solution，避免常规构建依赖 Oasis 检出。需要同级 `panda-auth-share` 和 `panda-oasis-server`；本轮拥有方验证来源为已合并提交 `2803912869cf45972f7d6c653c36807f74d1fec5`，契约由 Oasis #150 拥有。

准备符合 `PostgresTestBoundary` 的可丢弃 PostgreSQL 端点，设置 `PANDA_AUTH_TEST_POSTGRES`。登记的本机共享开发端点需显式设置 `PANDA_AUTH_TEST_SHARED_POSTGRES=1`，并使用本任务独有、符合该边界命名的 CREATEDB 角色。首次还原依赖后运行：

```bash
dotnet test tests/PandaAuth.OasisJointTests/PandaAuth.OasisJointTests.csproj --no-restore
```

测试复用 Auth 的实际 Program、OpenIddict 和隔离 PostgreSQL 协议夹具；Oasis 使用实际 Program、核验模块与本任务 SQLite 仓储。只用 TestServer 替代套接字传输，不替换签发、introspection 或成员判定。夹具先初始化发现/introspection，再检查客户端在原有三秒预算内的调用、错误组织、成员撤销及故障后拒绝；不证明冷启动一定能在三秒内成功，也不构成真实用户、生产 TLS 或生产登记验收。

夹具 finally 删除任务数据库、SQLite 和私有凭据目录；调用者完成全部检查后另行核对并删除自己创建的测试角色。未创建容器，不能清理其他会话资源。
