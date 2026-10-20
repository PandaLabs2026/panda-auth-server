# SecurityEvent / OpenIddict Token 保留策略

本任务默认关闭，不改变已有 `Auth:Audit` 审计日志及账号验证记录的清理任务。

新配置 `Auth:Retention`：

| 字段 | 默认 | 启用时范围 |
|---|---|---|
| Enabled | false | 显式批准后开启 |
| SecurityEventRetentionDays | 90 | 90–3650 |
| TokenRetentionDays | 14 | 14–3650 |

启用时启动后运行一次，此后每轮完成后等待 24 小时；通过 TimeProvider 计算同一轮 UTC 截止时间。每批 500，每类每轮最多处理 5000 条候选。

- SecurityEvent 仅删除 CreatedAt 严格早于截止点的记录。
- Token 必须过期满保留期，且 creation 也足够早；redemption 存在时必须足够早，状态为 redeemed 却缺 redemption 时间则保留。缺 creation/expiration 保留；边界相等保留；未过期的 revoked token 保留，避免破坏重放追踪。
- Token 使用 OpenIddict manager 删除，保留缓存/并发语义；并发变更跳过。其他失败在下一轮重试，不清理 authorization。
- 日志仅记删除/冲突计数与错误类型，不传递异常对象、消息、Token、凭据或记录内容。

清理不可通过代码回退恢复。禁用开关只能停止未来清理；本批没有设置生产开关、执行清理或发布。

`SecurityRetentionTests` 验证关闭、期限、时间边界、重放保留与错误脱敏；`SecurityRetentionPostgresTests` 在专用可丢弃数据库验证真实删除、5000 上限、并发 redemption 和失败重试。真实 PostgreSQL 专项未通过前不合并本组。
