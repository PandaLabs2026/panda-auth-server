#!/usr/bin/env bash
# 为 PandaAuth 配置本机 PostgreSQL 角色与最小权限。
# 以 sudo 执行；密码通过 psql \password 交互输入，不回显、不进入命令行参数。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo bash $0 执行。" >&2
  exit 1
fi

command -v psql >/dev/null || { echo "缺少 psql。" >&2; exit 1; }
sudo -u postgres psql -X -v ON_ERROR_STOP=1 <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', 'panda_auth')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'panda_auth')
\gexec
SELECT format('CREATE ROLE %I LOGIN', 'panda_auth_migrator')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'panda_auth_migrator')
\gexec
SELECT 'CREATE DATABASE panda_auth OWNER panda_auth_migrator'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'panda_auth')
\gexec
SQL

echo "请为 panda_auth 设置与服务器 panda-auth.env 中 DB_PASSWORD 完全一致的密码。"
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c '\password panda_auth'
echo "请为 panda_auth_migrator 设置一个独立的强随机密码。"
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c '\password panda_auth_migrator'

sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d panda_auth <<'SQL'
GRANT CONNECT ON DATABASE panda_auth TO panda_auth;
GRANT USAGE ON SCHEMA public TO panda_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO panda_auth;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO panda_auth;
SQL

HBA_FILE="$(sudo -u postgres psql -X -v ON_ERROR_STOP=1 -tA -c 'SHOW hba_file' | tr -d '[:space:]')"
HBA_RULE='host panda_auth panda_auth 127.0.0.1/32 scram-sha-256'
if ! grep -Fxq "$HBA_RULE" "$HBA_FILE"; then
  BACKUP="$(dirname "$HBA_FILE")/$(basename "$HBA_FILE").pre-panda-auth.$(date -u +%Y%m%d%H%M%S)"
  cp -a "$HBA_FILE" "$BACKUP"
  TEMP_FILE="$(mktemp "$HBA_FILE.XXXXXX")"
  { printf '%s\n' "$HBA_RULE"; cat "$HBA_FILE"; } > "$TEMP_FILE"
  chown --reference="$HBA_FILE" "$TEMP_FILE"
  chmod --reference="$HBA_FILE" "$TEMP_FILE"
  mv "$TEMP_FILE" "$HBA_FILE"
fi
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()' >/dev/null

SECRET_FILE=/home/jiayuhu/.config/panda-auth/panda-auth.env
if [ -r "$SECRET_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$SECRET_FILE"
  set +a
  if [ -n "${DB_PASSWORD:-}" ]; then
    PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U panda_auth -d panda_auth -X -v ON_ERROR_STOP=1 -tA -c 'SELECT 1' >/dev/null \
      || { echo "panda_auth 登录验证失败；检查 DB_PASSWORD 与刚设置的角色密码是否一致。" >&2; exit 1; }
  fi
  echo "请将新设的 migrator 密码保存为 DB_MIGRATOR_PASSWORD 到 $SECRET_FILE（权限 0600）。"
fi
echo "数据库角色、最小运行权限和本机 SCRAM 连接规则已配置。"
echo "发布前需验证 panda_auth 连接，并以 panda_auth_migrator 执行一次性迁移。"
