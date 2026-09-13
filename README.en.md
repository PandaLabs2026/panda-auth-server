# panda-auth-server

**PandaAuth by PandaLabs** · [简体中文](README.md)

> In development; no formally supported release yet. Access is by invitation or request. Implementation does not imply a verified release.

## Responsibility and boundaries

PandaAuth's IDP core uses ASP.NET Core Identity, EF Core/PostgreSQL and OpenIddict 7.7.0. Persistence, migrations, login controllers and service tests belong here; cross-process contracts come from sibling [panda-auth-share](https://github.com/PandaLabs2026/panda-auth-share).

## Current implementation and limitations

- [Protocol registration](src/PandaAuth.Server/Program.cs) enables Authorization Code with PKCE, Client Credentials and refresh tokens, with authorize/token/userinfo/logout/introspect/revoke endpoints configured.
- [Password hashing](src/PandaAuth.Server/Infrastructure/Security/Argon2idPasswordHasher.cs) uses Argon2id. [Rate limiting](src/PandaAuth.Server/Infrastructure/Security/LoginRateLimiter.cs) uses in-memory IP/account fixed windows; login audits are persisted to the database.
- [Key storage](src/PandaAuth.Server/Infrastructure/Security/SigningKeyStore.cs) checks signing-key rotation at startup, not periodically while running. Encryption keys are created only when missing; new/old key behavior needs testing.
- A [bulk revocation service](src/PandaAuth.Server/Features/Tokens/TokenRevocationService.cs) exists but is not connected to password changes, account suspension or deletion. Standard revocation handles the submitted token; it does not guarantee immediate invalidation across APIs or Cookie sessions.
- The [Web DemoClient](samples/PandaAuth.DemoClient) contains login, profile, refresh, single-token revocation and RP logout code. [Unit tests](tests/PandaAuth.Tests) cover hashing and rate limiting, not full protocol compliance.

**Static inspection found startup blockers:** Program.cs calls MapControllers without MVC service registration. The --migrate branch calls the Seeder before registering its OpenIddict dependency. Normal startup queries the key table first; Development only seeds and does not migrate. Seed.Enabled is not checked by the Seeder. These entry points are not a verified QuickStart; see G00/G04/G07 in the central release gates.

## Prerequisites, build and run entry points

Use the .NET SDK selected by [global.json](global.json) (currently 10.0.112 with latestFeature roll-forward). Clone repositories as siblings using the [workspace layout](https://github.com/PandaLabs2026/panda-auth/blob/main/WORKSPACE.md); cross-repository links require access. Commands below run from this repository root. They were statically checked, not executed, in this documentation change.

Share must be a sibling. Running requires an isolated development PostgreSQL database and suitable privileges; defaults are in [appsettings.Development.json](src/PandaAuth.Server/appsettings.Development.json). Demo credentials are for isolated development only, not production or public delivery records.

```bash
dotnet build PandaAuth.Server.slnx
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj
```

The following existing entry points describe intent and side effects. Fix and verify the startup blockers first; this is not a working installation sequence:

| Command | Purpose and side effects |
| --- | --- |
| `dotnet run --project src/PandaAuth.Server -- --migrate` | One-time migration/seed entry point; mutates the database, with a current seed dependency gap. Failure does not mean the database was unchanged |
| `dotnet run --project src/PandaAuth.Server` | Long-running server, development address http://localhost:9004; schema must already be prepared |
| `dotnet run --project samples/PandaAuth.DemoClient` | Web sample at http://localhost:5201; requires a working IDP, normally run in another terminal |

Protocol paths: `/connect/authorize`, `/connect/token`, `/connect/userinfo`, `/connect/logout`, `/connect/introspect`, `/connect/revoke`. OpenIddict supplies discovery/JWKS; health path is `/healthz`. Configured endpoints are not evidence of successful startup or protocol tests.

The [deployment guide](deploy/README.md) records migration rules and current initialization limitations. Production orchestration belongs to the coordination repository; normal startup does not replace one-time migration. Account lifecycle, verification codes and administration APIs are Phase 1 targets; Redis and overseas deployment are later targets.

## Roadmap and governance

Implementation targets are tracked in the [capability matrix](https://github.com/PandaLabs2026/panda-auth/blob/main/docs/open-source/capabilities.md) and [release gates](https://github.com/PandaLabs2026/panda-auth/blob/main/docs/open-source/release-readiness.md). Real product needs drive the roadmap; community requests are evaluated without delivery commitments. [Community/commercial boundaries](https://github.com/PandaLabs2026/panda-auth/blob/main/docs/open-source/strategy.md) describe scope, not delivered commercial products.

- [Security](SECURITY.md): selected private reporting channel, enablement unverified; no public vulnerability details.
- [Contributing](CONTRIBUTING.md): repository-specific checks and the shared contribution policy.
- [MIT License](LICENSE) for project-owned code/documentation, subject to [license scope](LICENSING.md); third-party terms remain applicable and brand images are excluded.
