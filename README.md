# panda-auth-server

PandaAuth 统一身份认证服务（IDP）核心——为熊猫实验室旗下全部应用提供 OIDC 1.0 / OAuth 2.0 统一认证。

## 内容

- `src/PandaAuth.Server` — OpenIddict 7.7.0 服务端（授权码+PKCE / 客户端凭证 / 刷新令牌）、Cookie 登录（Argon2id + IP/账号双维限流 + 登录审计）、签名密钥 DB 持久化与自动轮换、EF 迁移
- `samples/PandaAuth.DemoClient` — OIDC 登录闭环演示（授权码+PKCE → profile → 刷新 → 吊销 → RP 登出）
- `tests/PandaAuth.Tests` — 单元测试（Argon2id、限流分区，不依赖 DB/Docker）
- `deploy/` — 数据库初始化与迁移纪律

## 契约

端点常量、用户状态枚举等对外契约在 [panda-auth-share](../panda-auth-share)（须与本仓同级克隆）。

## 快速开始

```bash
dotnet run --project src/PandaAuth.Server         # http://localhost:9004（开发环境自动迁移+种子）
dotnet run --project samples/PandaAuth.DemoClient # http://localhost:5201（OIDC 闭环演示）
dotnet test                                        # 11 个单元测试
```

开发种子账号：`admin@pandalabs.cn` / `PandaAdmin#2026`（仅 Development）。

## 协议端点

`/connect/authorize` · `/connect/token` · `/connect/userinfo` · `/connect/logout` · `/connect/introspect` · `/connect/revoke` · `/.well-known/openid-configuration` · `/.well-known/jwks` · `/healthz`

种子客户端：`demo-public`（公共/PKCE）、`demo-web`（机密，密钥 `demo-web-secret-change-me`）、`demo-service`（机密，客户端凭证，密钥 `demo-service-secret-change-me`）——占位值，Phase 1 后台管理时改随机生成。

## Roadmap

- **Phase 0 ✅** 原型（三流程、Token 生命周期、部署物）
- **Phase 1** 用户全生命周期、验证码、后台管理 API（配 panda-auth-webadmin）、首个业务 App 接入
- **Phase 2** MFA、RBAC 细化、自助中心、异地登录检测
- **Phase 3** 海外实例（auth.pandalabs.cc，Issuer 走环境变量零代码切换）、Redis 分布式限流/缓存、高可用
