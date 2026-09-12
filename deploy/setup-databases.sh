#!/usr/bin/env bash
# 在共享 PostgreSQL 实例上创建 PandaAuth 的角色与库（惯例对齐 panda-server 的 setup-databases.sh）
#
# 前置：postgres 容器在运行（compose 项目 ~/app/postgresql）
# 用法：bash deploy/setup-databases.sh
set -euo pipefail

RUNTIME_ROLE="panda_auth"
RUNTIME_DB="panda_auth"
PG_CONTAINER="${PG_CONTAINER:-postgresql}"

read -r -s -p "请输入 postgres 管理密码: " PGPASSWORD_ADMIN
echo
read -r -s -p "请输入 panda_auth 运行账号密码（回车确认）: " RUNTIME_PASSWORD
echo

psql() {
  docker exec -i -e PGPASSWORD="$PGPASSWORD_ADMIN" "$PG_CONTAINER" psql -U postgres -v ON_ERROR_STOP=1 "$@"
}

# 角色与库（幂等）
psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$RUNTIME_ROLE'" | grep -q 1 \
  || psql -c "CREATE ROLE $RUNTIME_ROLE LOGIN PASSWORD '$RUNTIME_PASSWORD';"

psql -tAc "SELECT 1 FROM pg_database WHERE datname='$RUNTIME_DB'" | grep -q 1 \
  || psql -c "CREATE DATABASE $RUNTIME_DB OWNER $RUNTIME_ROLE;"

# PG15+：运行账号需在 public schema 上有 CREATE 权限才能执行 EF 迁移
psql -d "$RUNTIME_DB" -c "GRANT CREATE ON SCHEMA public TO $RUNTIME_ROLE;"
psql -d "$RUNTIME_DB" -c "GRANT ALL ON SCHEMA public TO $RUNTIME_ROLE;"

echo "完成：角色 $RUNTIME_ROLE 与库 $RUNTIME_DB 已就绪。"
echo "迁移（一次性容器执行，见元仓库 panda-auth/deploy/README.md）："
echo "  docker compose -p panda-auth --env-file .env --env-file ~/.config/panda-auth/panda-auth.env run --rm auth-server --migrate"
