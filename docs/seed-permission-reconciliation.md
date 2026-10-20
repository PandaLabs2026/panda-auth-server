# Seeder 权限对账

`Auth:Seed:PermissionReconciliationMode` 默认为 `AddMissing`：为启用的 Seeder 自有客户端补齐缺失权限，保留并报告多余权限数量，不撤销令牌。

`Exact` 仅对 `Auth:Seed:ExactPermissionClientIds` 显式列出的客户端删除多余权限；其他客户端仍按 AddMissing。名单只能包含启用的自有播种 profile（含显式启用的 demo），不能借此接管其他第一方或人工客户端。未知模式、未知/重复/禁用名单项在任何播种写入前失败。

权限删除、该客户端有效令牌撤销、安全审计在同一关系库事务内完成；失败回滚并重新加载应用实体，避免保留失败更新的缓存引用。仅增加或无变更时不撤销令牌；重复运行幂等。

权限修改沿用 Populate 往返及无 secret 参数的 UpdateAsync，不重新哈希现有密钥；已有配置密钥对账和回调名单逻辑仍各自生效。

## 配置与验证

仅在明确批准后设置模式为 `Exact` 并逐项配置客户端名单。空名单不删除任何客户端权限。默认模式不会删除权限，本次实现未开启任何生产配置。

启用前应保存经审批的客户端权限快照。代码回退不恢复已提交的权限删除，也不能恢复已撤销的令牌；后者需要用户重新认证。

`SeedPermissionPolicyTests` 覆盖策略与写前失败；`SeedPermissionPostgresTests` 使用专用可丢弃数据库验证哈希、撤销、审计、幂等和失败回滚。真实 PostgreSQL 专项未通过前，不合并本组。
