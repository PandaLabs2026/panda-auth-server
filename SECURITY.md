# 安全政策 / Security

当前元仓的可见性策略为暂保私有；原定元仓公开报告入口须在公共入口拆分、公开并完成渠道验证后才能使用，届时同步各仓政策链接。不能为了启用报告渠道而直接公开包含内部运维内容的现有元仓。

The current coordination repository is intended to remain private. Its planned public reporting entry must wait for separation and publication of the public coordination surface, followed by channel verification and synchronized policy links. Do not expose the existing internal-operations repository just to enable reporting.

本仓适用 PandaAuth [统一安全政策](https://github.com/PandaLabs2026/panda-auth/blob/main/SECURITY.md)。当前为研发阶段，尚无正式受支持发行版，不承诺固定响应或修复时限。

选定报告渠道是元仓 **PandaLabs2026/panda-auth 的 GitHub Private Vulnerability Reporting**，当前启用状态未核验。公开发布窗口需管理员开启并验证入口和通知后才能宣布可用；不提供未经确认的安全邮箱或假定可用的报告表单。受邀协作者在此之前使用已有私密协作渠道联系维护者。

不要在公开 Issue、PR 或讨论中提交漏洞细节、凭据和用户数据。渠道启用后，报告注明本仓名称、受影响版本/提交、影响和脱敏复现。支持范围与协调披露以统一政策为准；受支持社区版本安全修复不为商业订阅故意延迟。

This repository follows the [central security policy](https://github.com/PandaLabs2026/panda-auth/blob/main/SECURITY.md). It is in development with no formally supported release or fixed response/remediation SLA. The selected channel is GitHub Private Vulnerability Reporting in PandaLabs2026/panda-auth; enablement is unverified. An administrator must enable and verify the entry and notifications during the public launch window before announcing availability. Until then, invited collaborators use existing private channels; no unverified mailbox or reporting form is offered. Do not disclose vulnerabilities or secrets publicly. Once enabled, include this repository, the affected revision, impact and sanitized reproduction. Supported community fixes are not deliberately delayed for paid subscribers; support and coordinated disclosure follow the central policy.
