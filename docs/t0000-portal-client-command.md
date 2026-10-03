# t0000 Portal 专用客户端操作

本入口落实已合并 Auth 元仓 `83e16769c3d5846b203002dd26390b2aa3f536b4` 的 t0000 Portal 设计 §3；不提供通用客户端管理或生产授权。登记与镜像发布是两个显式步骤。

## 执行边界

- 唯一命令为 `--register-portal-client` 或 `--unregister-portal-client`，各自必须是唯一参数。混用、重复、未知参数在配置/provider/密钥初始化前关闭。正常 Server 保留无参数及原 `--migrate`；实际标准 host bootstrap 仅接受明确的 environment/applicationName/contentRoot 参数（contentRoot仅绝对现存目录；任意配置键仍拒绝）。
- 专用命令提前返回，不初始化 DP/SigningKeyStore/MFA/DbSeeder，不迁移，不监听 HTTP，不启动后台服务。只使用受控 `ConnectionStrings:Default` runtime provider，不选择 Migration，不创建角色或权限。
- 命令仅支持 Linux x64，实际 UID/GID 必须为 `1003:1003`（SH host operator jiayuhu）；常驻 Server 的 UID1654 不变。实际 EUID、输入 owner 与已登记 machine marker共同绑定固定 executor；请求 JSON 不构成授权。
- 外部 controller 负责用户已授权计划、root-reviewed protected request、真实 merged source SHA、窗口、目标及 Default provider snapshot/digest/runtime role复核。程序不验证 git merge/审批事实，也不自行宣称生产授权。错误注入受控 provider会导致误连风险，故真实 one-shot 前必须完成这些门禁。

## 输入与文件

固定 container 路径 `/etc/panda-auth/t0000-portal/registration-request.json` 和 `registration-rollback.json`。输入目录 owner1003/mode0700，请求文件 owner1003/mode0400，单 hardlink、regular file，禁止路径及 parent symlink、group/other可写 parent。读取时比较 path/FD inode、device、mode、owner，限制32KiB。程序不接受自选路径。

`machine.json` 只读 mount自已登记 HOST `/home/jiayuhu/app/pandalabs/machine.json`；实际 owner1003、nonlink、单 hardlink，禁止 group/other写；允许现有非秘密 marker0644，`machine_id` 必须为 `tcloud-sh-01`。不得 chmod/chown 全局 provider。一次性命令仅挂 protected input和受控 existing Default env；不挂 DP/signing key 或其它应用数据。

JSON为闭合对象，递归拒绝重复键（包括嵌套对象）、未知请求字段、错误类型及深度>8。UTF-8原字节 SHA256覆盖空白/顺序；重试必须保留完整原文件。

共同必需字段：`schemaVersion`（整数1）、`deploymentKind`=`legacy-t0000-portal`、`tenantId`=`t0000`、`zone`=`s001`、`machineId`=`tcloud-sh-01`、`operationId`（canonical lowercase UUID-D）、`authMetaSource`/`authServerSource`（完整40 lowercase SHA）、`planReference`/`executionReference`（安全 ASCII引用）、`executor`=`jiayuhu@tcloud-sh-01`、`maintenanceStartUtc`/`maintenanceEndUtc`/`validUntilUtc`（严格 `yyyy-MM-ddTHH:mm:ssZ`）。维护窗口为正、最多24h，validUntil不早于窗口结束且距开始最多90天。首次写入必须处于窗口；恢复可在窗口后但不能超过请求及原记录有效期。

登记另需 `issuer`=`https://t0000-auth.s001.pandalabs.cn/`、`redirectUri`=`https://t0000.s001.pandalabs.cn/callback`、`postLogoutRedirectUri`=`https://t0000.s001.pandalabs.cn/callback/logout`。`clientId`可省略由产品实际生成，或 owner批准的3–64 ASCII字母/数字/dot/underscore/hyphen。回滚另需原 receipt中的 `clientId`、`requestDigest`、`registrationDigest`，无 issuer/URI字段；请求自己的原字节 digest另行绑定。

## 事务、恢复和回滚

OpenIddict真实 manager、同 scoped DbContext、AdminAuditWriter 在 PostgreSQL Serializable整事务内运行。每次 persistent operation lookup在ID生成前；禁用 Core entity cache。40001、死锁、唯一冲突及 commit acknowledgement不确定时最多4次整事务 fresh scope/context，成功仅在确认 commit后输出。

`portal.client.register`/`portal.client.unregister`、targetType=`portal-client-operation` 的 audit记录保存原原字节请求digest、原完整receipt、application ID和有效期。创建 Properties `pandalabs.t0000-portal.creation`绑定 target/op/request/registration digest。原 audit与当前客户端冲突、丢失或终态撤销关闭；残留创建 marker无审计时不得生成第二个 ID。现有客户端只精确读回，不覆盖；结果分类仍为existing。

回滚仅允许原created：审计、marker、operation/client/digests、当前descriptor及固定target必须匹配，并且 authorization/token引用均不存在；删除和终态审计同事务，禁止 cascade。重复回滚返回原回执；登记重试不得重建已撤销客户端。镜像回滚不代表登记回滚。

普通日期 retention继续处理其它 admin audit；专用恢复与终态 audit narrowly保留，不按日期删除。此选择保住有效期及永久终态、防止操作失忆重新创建，成本是极少量专用操作记录无限期占用存储；以后若要删除必须另有不丢终态的治理方案。

## 回执 wire

登记 stdout只有一行 UTF-8 JSON加 trailing LF，固定23字段：`schemaVersion,deploymentKind,tenantId,zone,machineId,operationId,requestDigest,clientId,result,clientType,consentType,issuer,redirectUris,postLogoutRedirectUris,permissions,requirements,registrationDigest,authMetaSource,authServerSource,planReference,executionReference,executor,observedUtc`。

`result`为created/existing，clientType public、consentType implicit；两个 URI数组为精确 singleton。permissions精确集合 `ept:authorization,ept:token,ept:end_session,gt:authorization_code,rst:code,scp:profile`；requirements精确 `[ft:pkce]`。无 refresh/offline/email/roles/client_credentials/secret。openid按框架标准处理。

registrationDigest为真实 manager读回 descriptor的compact UTF-8 JSON SHA256；固定属性顺序 `clientId,clientType,consentType,issuer,redirectUris,postLogoutRedirectUris,permissions,requirements`，数组Ordinal排序去重，标准JSON escaping；没有op/source/secret字段。恢复返回持久原receipt字符串，不更新classification/UTC、不重序列化。consumer应保留原stdout bytes（含LF）、canonical Base64及SHA256，不重算registrationDigest。

回滚stdout为独立unregistered终态回执，包含原 requestDigest、rollbackRequestDigest、原client/registrationDigest及相同target/source/plan/executor/UTC引用；不能用作登记凭证。错误stdout空，stderr只固定 `portal-client-command-closed` 或 `portal-client-command-retryable`及已验证operationId，退出码1/2；不输出原异常、连接串、env或token。

## 验证范围

隔离 PostgreSQL tests实际使用 manager/共享事务/audit，覆盖丢回执、commit不确定前后、并发Serializable重试、existing拒回滚、terminal稳定、audit失败、引用保护和retention。真实 UID1003只读任务容器运行已发布 Auth DLL，证明早期模式无keys/seed/listener；真实 HTTP WAF用实际登记descriptor证明无id_token_hint、client_id+精确callback公开logout清Cookie，错误callback拒绝。它们不证明已完成生产登记、真实部署或client readiness；实际release需要独立controller门禁。
