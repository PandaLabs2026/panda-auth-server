<!-- GENERATED FILE — DO NOT EDIT. Source: pandalabs/docs/topology/topology.json; revision: 1. -->

# PandaLabs 拓扑快照

本文件由协调仓生成，修改请回到协调仓的 docs/topology/topology.json。

## 机器

| 机器 | 主机名 | 角色 |
|---|---|---|
| windows-dev | — | development、build |
| tcloud-sg-01 | tcloud-sg-01.pandalabs.cc | website-global、website-build |
| tcloud-sh-01 | tcloud-sh-01.pandalabs.cc | website-cn、product-production |
| aliyun-sh-01 | aliyun-sh-01.pandalabs.cc | cold-standby、read-only、recovery-rehearsal |

## 项目

- panda-auth：active
- panda-asst：active
- panda-asst-server：active
- panda-asst-mobile：active
- panda-asst-website：active
- panda-asst-webapp：active
- panda-asst-webadmin：active
- oasis：active
- oasis-admin：active
- oasis-server：active
- oasis-tadmin：active
- oasis-website：active
- panda-auth-admin：active
- panda-auth-me：active
- panda-auth-sdk：active
- panda-auth-server：active
- panda-auth-share：active
- panda-auth-website：active

## 数据库与共享数据服务

- **pandalabs-postgres-production**（shared-postgresql）：机器 tcloud-sh-01，127.0.0.1:5432；数据库 panda、oasis、panda_auth；local TCP from production containers via 127.0.0.1:5432; credentials from server-only secret files。
- **development-postgresql**（per-machine-development）：机器 windows-dev、tcloud-sg-01，—:—；数据库 panda_dev、oasis-dev、disposable test databases；localhost:5432 or an explicitly supplied test connection string。
- **aliyun-panda-auth-legacy**（legacy-rollback-standby）：机器 aliyun-sh-01，—:—；数据库 —；do not publish, migrate, or use for normal application access。

## 关键配置路径

- **machine-marker-linux**：/home/jiayuhu/app/pandalabs/machine.json；declares the canonical machine identity for topology checks；机器 tcloud-sg-01、tcloud-sh-01、aliyun-sh-01；不含密钥内容。
- **machine-marker-windows**：%ProgramData%\PandaLabs\machine.json；declares the Windows development machine identity；机器 windows-dev；不含密钥内容。
- **caddy-global**：/etc/caddy/Caddyfile；global Caddy options and site imports；机器 tcloud-sg-01、tcloud-sh-01；不含密钥内容。
- **caddy-site-snippets**：/home/jiayuhu/app/caddy/*.caddy；user-owned Caddy site blocks and reverse-proxy routes；机器 tcloud-sg-01、tcloud-sh-01；不含密钥内容。
- **website-artifacts**：/home/jiayuhu/app/pandalabs-website/{cn,global}；static website release artifacts served by Caddy；机器 tcloud-sg-01、tcloud-sh-01；不含密钥内容。
- **panda-runtime-env**：/home/jiayuhu/app/panda/deploy/.env；Panda Assistant production image pins and non-secret Compose runtime configuration；机器 tcloud-sh-01；含敏感配置，禁止复制内容。
- **panda-secret-env**：~/.config/panda/panda.env；Panda Assistant production secrets and private runtime values；机器 tcloud-sh-01；含敏感配置，禁止复制内容。
- **panda-auth-runtime-env**：/home/jiayuhu/app/panda-auth/deploy/.env；PandaAuth Compose image pins and non-secret deployment values；机器 tcloud-sh-01；含敏感配置，禁止复制内容。
- **panda-auth-secret-env**：~/.config/panda-auth/panda-auth.env；PandaAuth database, issuer and service secrets；机器 tcloud-sh-01；含敏感配置，禁止复制内容。
- **panda-auth-deploy-worktree**：/home/jiayuhu/app/panda-auth/deploy；PandaAuth production Compose and release control files; not application source；机器 tcloud-sh-01；不含密钥内容。
- **oasis-runtime-env**：/home/jiayuhu/app/oasis/.env；Oasis image pins, database selector and runtime values；机器 tcloud-sh-01；含敏感配置，禁止复制内容。
- **oasis-pg-admin-env**：~/.config/oasis/pg-conn.env；Oasis PostgreSQL administration/test connection metadata；机器 tcloud-sg-01、tcloud-sh-01；含敏感配置，禁止复制内容。
- **shared-postgres-compose**：/home/jiayuhu/app/postgresql/docker-compose.yml；shared pandalabs-postgres deployment definition；机器 tcloud-sh-01；含敏感配置，禁止复制内容。
- **panda-auth-db-setup**：/home/jiayuhu/app/panda-auth/deploy/setup-databases.sh；idempotent PandaAuth roles and database permission setup；机器 tcloud-sh-01；不含密钥内容。

## 服务与入口

- **website-cn**：机器 tcloud-sh-01；static-site；项目 pandalabs-website；/home/jiayuhu/app/pandalabs-website/cn。
- **website-global**：机器 tcloud-sg-01；static-site；项目 pandalabs-website；/home/jiayuhu/app/pandalabs-website/global。
- **panda-auth-stack**：机器 tcloud-sh-01；docker-compose；项目 panda-auth；panda-auth。
- **panda-asst-stack**：机器 tcloud-sh-01；docker-compose；项目 panda-asst；panda-asst。
- **oasis-stack**：机器 tcloud-sh-01；docker-compose；项目 oasis；oasis。
- **shared-postgres**：机器 tcloud-sh-01；docker；项目 —；pandalabs-postgres。
- 入口 **pandalabs.cn**：https → website-cn，验收 GET /。
- 入口 **pandalabs.cc**：https → website-global，验收 GET /。
- 入口 **assistant.pandalabs.cn**：https → panda-asst-stack，验收 GET /healthz。
- 入口 **auth.pandalabs.cn**：https → panda-auth-stack，验收 GET /.well-known/openid-configuration。
- 入口 **oasis.pandalabs.cn**：https → oasis-stack，验收 GET /healthz。

## 依赖、构建与发布

- pandalabs-website → assistant.pandalabs.cn：release-gate-product-link。
- panda-auth-stack → pandalabs-postgres-production：runtime-and-migration-database。
- panda-asst-stack → pandalabs-postgres-production：runtime-database。
- oasis-stack → pandalabs-postgres-production：runtime-database。
- panda-auth-stack → caddy-site-snippets：public-routing。
- panda-asst-stack → caddy-site-snippets：public-routing。
- oasis-stack → caddy-site-snippets：public-routing。
- 构建 **website-build**：在 tcloud-sg-01 执行；npm ci && npm run build:cn && npm run build:global；产物 temporary variant artifacts；交付 rsync mirror。
- 构建 **panda-auth-build**：在 tcloud-sg-01 执行；panda-auth/deploy/release-remote.sh；产物 immutable service images；交付 verified image transfer to tcloud-sh-01。
- 构建 **panda-asst-build**：在 tcloud-sg-01 执行；release.sh；产物 immutable service images；交付 verified image transfer to tcloud-sh-01。
- 构建 **oasis-build**：在 tcloud-sg-01 执行；deploy/release-local.sh；产物 immutable service images；交付 verified image transfer to tcloud-sh-01。
- 发布 **website-mirror-release**：构建机 tcloud-sg-01；目标 tcloud-sg-01、tcloud-sh-01；禁止源码直发生产；rebuild a prior committed variant and mirror it。
- 发布 **product-image-release**：构建机 tcloud-sg-01；目标 tcloud-sh-01；禁止源码直发生产；禁止生产构建；restore prior image tag; database rollback is separate。

## 备份、访问与生命周期

- 备份 **panda-auth-db-backups**：/home/jiayuhu/app/panda-auth/backups；pg_dump -Fc；恢复验证 isolated PostgreSQL 18 container before production restore。
- 备份 **oasis-db-backups**：/home/jiayuhu/app/oasis/backups；pg_dump -Fc；恢复验证 isolated PostgreSQL 18 container before production restore。
- 备份 **panda-asst-release-backups**：/home/jiayuhu/app/panda/deploy/backups；release-specific database backup；恢复验证 release procedure and manual verification。
- unknown_machine：block。
- root_login：forbidden。
- source_deploy_to_production：forbidden。
- production_delivery：artifact-mirror-only。
