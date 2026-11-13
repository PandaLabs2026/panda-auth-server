# panda-auth-server

**PandaAuth by PandaLabs** · [简体中文](README.zh-CN.md)

**Official page [pandalabs.cc](https://pandalabs.cc/products/panda-auth/)** · Chinese site [pandalabs.cn](https://pandalabs.cn/products/panda-auth/) · [PandaLabs product suite](https://pandalabs.cc/products/)

> The PandaAuth suite is currently in **Community Preview 0.2.0-preview.1** — deployed in production and open to early community users. The stable Community Release 1.0.0 has not shipped yet. Access is by invitation or request.

## Responsibility and boundaries

PandaAuth's IDP core uses a self-owned user and role store, EF Core/PostgreSQL and OpenIddict 7.7.0. Persistence, migrations, login controllers and service tests belong here; cross-process contracts come from sibling [panda-auth-share](https://github.com/PandaLabs2026/panda-auth-share). ASP.NET Core Identity is no longer the runtime user-store authority.

## Current implementation and limitations

- [Protocol registration](src/PandaAuth.Server/Program.cs) enables Authorization Code with PKCE, Client Credentials and refresh tokens, with authorize/token/userinfo/logout/introspect/revoke endpoints configured.
- [Password hashing](src/PandaAuth.Server/Infrastructure/Security/Argon2idPasswordHasher.cs) uses Argon2id. [Rate limiting](src/PandaAuth.Server/Infrastructure/Security/LoginRateLimiter.cs) uses in-memory IP/account fixed windows; login audits are persisted to the database.
- The [live signing-key ring](src/PandaAuth.Server/Infrastructure/Security/SigningKeyRing.cs) refreshes every 60 seconds, prepublishes successors and retains verification keys for the full refresh-token window. Stale snapshots and invalid schedules stop new issuance and fail health checks. Encryption keys remain unchanged. First activation requires the additive migration with old key-management binaries stopped; source integration is separate from production deployment.
- Admin APIs require the dedicated administration scope/audience and trusted human presenter. [Account security versions](src/PandaAuth.Server/Infrastructure/Security/AccountSecurityVersion.cs) are inherited from the verified login and checked against current account state; selected credential/account changes commit their state, revocation and audit together. Cookie stamp validation reads the account on every request.
- A [bulk revocation service](src/PandaAuth.Server/Features/Tokens/TokenRevocationService.cs) is connected through `SessionSecurityService` to password changes, suspension, role changes, MFA reset, external-identity unlink and deletion paths. Standard revocation handles submitted tokens; online token-entry validation makes revocation effective for this service's APIs, but it does not guarantee immediate invalidation of offline access tokens, external-resource-server caches or every Cookie session.
- The [Web DemoClient](samples/PandaAuth.DemoClient) contains login, profile, refresh, single-token revocation and RP logout code. [Tests](tests/PandaAuth.Tests) cover unit behavior, real PostgreSQL/HTTP protocol flows, deterministic security races, failure injection and separate-process transaction/key behavior. They do not constitute complete protocol compliance or production acceptance.

## Prerequisites, build and run entry points

Use the .NET SDK selected by [global.json](global.json) (currently 10.0.112 with latestFeature roll-forward). This repository can be built without the private coordination repository, but the public Share repository must be cloned beside it. Commands below run from this repository root.

```bash
git clone https://github.com/PandaLabs2026/panda-auth-server.git
git clone https://github.com/PandaLabs2026/panda-auth-share.git
cd panda-auth-server
```

Share must be a sibling. Running requires an isolated development PostgreSQL database and suitable privileges; defaults are in [appsettings.Development.json](src/PandaAuth.Server/appsettings.Development.json). Demo credentials are for isolated development only, not production or public delivery records.

```bash
bash scripts/verify-local.sh
```

The local verification entry checks the shared machine-capacity policy, workspace, task temp directory, Server/Share outputs and NuGet/.NET CLI caches before restore, build and test. Without `PANDA_AUTH_TEST_POSTGRES`, database-dependent tests are explicitly skipped; this does not count as database integration acceptance. Container builds must run through the organization execution wrapper so Docker host storage is admitted before Docker starts.

The following existing entry points describe intent and side effects. The startup blockers are fixed, but these commands are still **not an accepted installation sequence** (end-to-end acceptance of the authentication flow is incomplete):

| Command | Purpose and side effects |
| --- | --- |
| `dotnet run --project src/PandaAuth.Server -- --migrate` | One-time migration/seed entry point; mutates the database. Failure does not mean the database was unchanged. Seeding is an **upsert reconciliation**: existing clients are corrected (for example me-web's redirect/post-logout whitelists are replaced wholesale when they differ from configuration), and a client secret is rewritten only when the stored hash no longer validates |
| `dotnet run --project src/PandaAuth.Server -- --migrate-admin-resource-only` | Existing-instance activation migrator using the Migration connection and DB lease. Requires the existing confidential `admin-web`; rejects conflicting grants/resource audiences before DDL. Applies migrations, then transactionally creates the administration scope if absent and adds only its permission to `admin-web`. Preserves accounts, secrets, callbacks, other clients and tokens; does not run general seeding or initialize key management/listeners. This mutating command requires the owning cold-maintenance/backup/restore/authorization workflow; failure after DDL requires forward recovery. |
| `dotnet run --project src/PandaAuth.Server` | Long-running server, development address http://localhost:9004; schema must already be prepared |
| `dotnet run --project samples/PandaAuth.DemoClient` | Web sample at http://localhost:5201; requires a working IDP, normally run in another terminal |

Protocol paths: `/connect/authorize`, `/connect/token`, `/connect/userinfo`, `/connect/logout`, `/connect/introspect`, `/connect/revoke`. OpenIddict supplies discovery/JWKS; health path is `/healthz`. Configured endpoints are not evidence of successful startup or protocol tests.

The [deployment guide](deploy/README.md) records migration rules and current initialization limitations. Production orchestration belongs to the coordination repository; normal startup does not replace one-time migration. Self-service password reset via verification codes and the management API are implemented (see the scope notes above).

The name-only [runtime configuration reference](deploy/.env.example) lists selected Server process environment keys without values. Production orchestration and secret delivery belong to the PandaAuth coordination repository; this reference is not a deployable env file.

## Roadmap and governance

Product roadmap, release gates and community/commercial boundaries remain maintainer-governed until a formal public release. This README documents only the independently reproducible Server build and runtime boundary.

- [Security](SECURITY.md): selected private reporting channel, enablement unverified; no public vulnerability details.
- [Contributing](CONTRIBUTING.md): repository-specific checks and the shared contribution policy.
- [MIT License](LICENSE) for project-owned code/documentation, subject to [license scope](LICENSING.md); third-party terms remain applicable and brand images are excluded.

## Production bridge proxy configuration

Production topology and release commands are maintained in the sibling meta repository's
`deploy/README.md`. The default bridge stack sets both `PANDA_AUTH_TENANT_NETWORK_MODE=bridge`
and `PANDA_AUTH_TRUSTED_PROXY` to the allocation's exact IPv4 network gateway.
Subnet peers and loopback are not trusted in bridge mode. The application's image defaults
are development defaults, not production port assignments.

### CloudConfig 定向身份登记

`PandaAuth.Server --register-cloud-config-only` 复用既有 CloudConfig 登记组件，只登记五个原 scope、专用内省 client，并给已存在的 `FirstPartyClients.CloudConsoleWeb` 增加对应权限。不执行 Schema 迁移或全量 DbSeeder，不创建 Console/Fleet/用户/角色，不启动 Web 或密钥任务。错误参数（包括与 `--migrate` 混用）失败关闭，不落入服务启动。

执行条件为已批准的正式镜像、原迁移连接与就绪 Schema，以及一次性受保护配置中显式开启 `Auth:Seed:Enabled`、`Auth:Seed:CloudConfig:Enabled`、`Auth:Seed:CloudConsoleWeb:Enabled`；issuer 必须匹配共享契约，专用 `Auth:Seed:CloudConfig:ClientSecret` 不能为空。本入口拒绝 FleetReadEnabled，避免把本批扩大到 Fleet client。配置及秘密只经服务器受保护材料供应，不在聊天、命令参数或日志中传递；生产授权、备份/恢复、镜像来源及执行入口仍按 [Auth 部署正本](../panda-auth/deploy/README.md)准备具体批次。本命令存在不授予执行权限。

入口持有原数据库租约，拒绝待迁移 Schema；整个登记及 Console 权限追加在一个 Serializable 事务中完成。资源映射、内省 client 类型/权限或专用 secret 漂移即回滚；不静默轮换、不改 Console 原 secret/hash、回调或其它属性，不删原权限或改变其它客户端。重入复用同一身份。成功仅输出 `cloud-config-registration-only-v1` 脱敏结果；失败不回显连接、SQL、secret 或底层异常，不自动重试。关闭 seed 开关、撤销代码或镜像回退都不会撤销已登记权限/token，实际撤销另按精确批次处理。

本入口不注册 API 目标授权、Worker/Helper、mTLS/签名身份，也不证明真实人类登录、配置消费或最终验收；这些仍在原 OrgConfig 首批部署/真实使用批次完成。
