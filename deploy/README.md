# PandaAuth.Server 部署说明

生产部署总清单（compose、Caddy、发布脚本）在元仓库 `panda-auth/deploy/`，本目录只放 Server 专属内容。

## 数据库

共享 PostgreSQL 实例（compose 项目 `~/app/postgresql`）上创建角色与库：

```bash
bash deploy/setup-databases.sh    # 角色 panda_auth + 库 panda_auth（幂等）
```

## 迁移纪律（对齐 panda-server）

- 运行账号日常无 DDL 压力；结构变更通过 `--migrate` 一次性容器执行（命令见元仓上线清单）
- 迁移前备份：
  ```bash
  docker exec postgresql pg_dump -U postgres -Fc panda_auth > ~/app/panda-auth/backups/pre-<变更>-$(date -u +%Y%m%dT%H%M%SZ).dump
  ```
- 恢复演练：用临时 postgres:18 容器验证 dump 可恢复后再执行迁移

## 本地开发

```bash
dotnet tool restore
dotnet ef migrations add <Name> --project src/PandaAuth.Server   # 设计时工厂，无需数据库
dotnet run --project src/PandaAuth.Server                        # http://localhost:9004（自动迁移+种子）
```

本地需要 PostgreSQL 15+（连接串见 `appsettings.Development.json`：库 `panda_auth_dev`，账号 `panda_auth/panda_auth`）。

## 镜像构建（跨仓）

```bash
# 在 panda-auth 工作区根执行（需要同级克隆 panda-auth-share）：
docker build -f panda-auth-server/Dockerfile -t panda-auth-server:latest .
```
