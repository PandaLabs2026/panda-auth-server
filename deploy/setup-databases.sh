#!/usr/bin/env bash
# Configure the local PostgreSQL roles and least-privilege access for PandaAuth.
# Run with sudo. Passwords are entered through psql's hidden interactive prompt.
#
# 默认规则（均可用环境变量覆盖，无个人路径硬编码）：
#   RUN_USER    运行服务、并且必须拥有密钥文件的操作系统账号。
#               默认取 SUDO_USER（sudo 调用者），非 sudo 直接以 root 执行时取当前用户；
#               可用 PANDA_AUTH_RUN_USER 显式指定。
#   SECRET_FILE 密钥文件（含 DB_PASSWORD / DB_MIGRATOR_PASSWORD）的路径，
#               默认 <RUN_USER 家目录>/.config/panda-auth/panda-auth.env；
#               可用 PANDA_AUTH_SECRET_FILE 显式指定。
#               文件必须属于 RUN_USER 且权限为 0600，否则脚本拒绝执行。
#   PANDA_AUTH_PGHOST / PANDA_AUTH_PGPORT
#               可选的 PostgreSQL 管理连接地址；默认使用宿主机 Unix socket。
#   PANDA_AUTH_HBA_FILE
#               可选的宿主机可见 pg_hba.conf 路径；默认从 PostgreSQL 查询。
#   PANDA_AUTH_HBA_HOSTS 允许的受限 TCP 来源 CIDR，默认仅 127.0.0.1/32 和 ::1/128。
# 例：sudo PANDA_AUTH_SECRET_FILE=/srv/panda-auth/panda-auth.env bash setup-databases.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with: sudo bash $0" >&2
  exit 1
fi

command -v psql >/dev/null || { echo "psql is required." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required to read the env file safely." >&2; exit 1; }

postgres_psql() {
  if [ -n "${PANDA_AUTH_PGHOST:-}" ]; then
    sudo -u postgres env PGHOST="$PANDA_AUTH_PGHOST" PGPORT="${PANDA_AUTH_PGPORT:-5432}" psql "$@"
  else
    sudo -u postgres psql "$@"
  fi
}

RUN_USER="${PANDA_AUTH_RUN_USER:-${SUDO_USER:-$(id -un)}}"
if ! RUN_UID="$(id -u "$RUN_USER" 2>/dev/null)" || [ -z "$RUN_UID" ]; then
  echo "Cannot resolve runtime user '$RUN_USER'; set PANDA_AUTH_RUN_USER explicitly." >&2
  exit 1
fi

SECRET_FILE="${PANDA_AUTH_SECRET_FILE:-}"
if [ -z "$SECRET_FILE" ]; then
  RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
  if [ -z "$RUN_HOME" ]; then
    echo "Cannot resolve the home directory of '$RUN_USER'; set PANDA_AUTH_SECRET_FILE explicitly." >&2
    exit 1
  fi
  SECRET_FILE="$RUN_HOME/.config/panda-auth/panda-auth.env"
fi

if [ ! -f "$SECRET_FILE" ] || [ ! -r "$SECRET_FILE" ]; then
  echo "Missing or unreadable $SECRET_FILE; create it with mode 0600 first." >&2
  exit 1
fi
SECRET_UID="$(stat -c '%u' "$SECRET_FILE")"
SECRET_MODE="$(stat -c '%a' "$SECRET_FILE")"
if [ "$SECRET_UID" != "$RUN_UID" ] || [ "$SECRET_MODE" != "600" ]; then
  echo "$SECRET_FILE must be owned by $RUN_USER (uid $RUN_UID) and have mode 0600." >&2
  exit 1
fi

PG_VERSION_NUM="$(postgres_psql -X -v ON_ERROR_STOP=1 -tA -c 'SHOW server_version_num' | tr -d '[:space:]')"
if [[ ! "$PG_VERSION_NUM" =~ ^18[0-9]{4}$ ]]; then
  echo "Expected PostgreSQL 18 on the selected postgres connection; refusing to modify another cluster." >&2
  exit 1
fi

# Parse only a plain DB_PASSWORD assignment; never source a secrets file as root.
DB_PASSWORD="$(python3 - "$SECRET_FILE" <<'PY'
import re
import sys

values = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        line = line.rstrip("\r\n")
        match = re.fullmatch(r"\s*DB_PASSWORD\s*=\s*(.*?)\s*", line)
        if match:
            value = match.group(1)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if not value or "\n" in value or "\r" in value:
                raise SystemExit("DB_PASSWORD must be a non-empty single-line value.")
            values.append(value)
if len(values) != 1:
    raise SystemExit("Expected exactly one DB_PASSWORD assignment in panda-auth.env.")
print(values[0], end="")
PY
)"

postgres_psql -X -v ON_ERROR_STOP=1 <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', 'panda_auth')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'panda_auth')
\gexec
SELECT format('CREATE ROLE %I LOGIN', 'panda_auth_migrator')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'panda_auth_migrator')
\gexec
ALTER ROLE panda_auth LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE panda_auth_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
DO $$
DECLARE granted_role text;
BEGIN
  FOR granted_role IN
    SELECT parent.rolname
    FROM pg_auth_members membership
    JOIN pg_roles parent ON parent.oid = membership.roleid
    JOIN pg_roles member ON member.oid = membership.member
    WHERE member.rolname = 'panda_auth'
  LOOP
    EXECUTE format('REVOKE %I FROM panda_auth', granted_role);
  END LOOP;
  FOR granted_role IN
    SELECT parent.rolname
    FROM pg_auth_members membership
    JOIN pg_roles parent ON parent.oid = membership.roleid
    JOIN pg_roles member ON member.oid = membership.member
    WHERE member.rolname = 'panda_auth_migrator'
  LOOP
    EXECUTE format('REVOKE %I FROM panda_auth_migrator', granted_role);
  END LOOP;
END
$$;
SELECT 'CREATE DATABASE panda_auth OWNER panda_auth_migrator'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'panda_auth')
\gexec
ALTER DATABASE panda_auth OWNER TO panda_auth_migrator;
SQL

echo "Set panda_auth to the DB_PASSWORD value already stored in $SECRET_FILE."
postgres_psql -X -v ON_ERROR_STOP=1 -c '\password panda_auth'
echo "Set a separate strong password for panda_auth_migrator."
postgres_psql -X -v ON_ERROR_STOP=1 -c '\password panda_auth_migrator'

postgres_psql -X -v ON_ERROR_STOP=1 -d panda_auth <<'SQL'
REASSIGN OWNED BY panda_auth TO panda_auth_migrator;
ALTER SCHEMA public OWNER TO panda_auth_migrator;
DO $$
DECLARE object_name text;
BEGIN
  FOR object_name IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO panda_auth_migrator', object_name);
  END LOOP;
  FOR object_name IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO panda_auth_migrator', object_name);
  END LOOP;
END
$$;
REVOKE ALL ON DATABASE panda_auth FROM PUBLIC;
REVOKE ALL ON DATABASE panda_auth FROM panda_auth;
GRANT CONNECT ON DATABASE panda_auth TO panda_auth;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM panda_auth;
GRANT USAGE ON SCHEMA public TO panda_auth;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM panda_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO panda_auth;
-- 运行角色不得删除签名密钥：代码（Infrastructure/Security/SigningKeyStore）只新增密钥与置 Retired，
-- 从无删除路径。收紧为 SELECT/INSERT/UPDATE 可消除「运行账号被攻陷即可抹除密钥历史」的破坏面。
-- 表可能尚未迁移出来（首次在空库上执行），故仅在存在时收紧。
SELECT 'REVOKE DELETE ON TABLE public.signing_keys FROM panda_auth'
WHERE to_regclass('public.signing_keys') IS NOT NULL
\gexec
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM panda_auth;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO panda_auth;
-- 默认权限只作用于此后新建的表：signing_keys 若被重建（例如迁移中 drop/create）会重新带上 DELETE，
-- 届时需重跑本脚本收紧（脚本幂等）。
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO panda_auth;
-- 自检：signing_keys 存在时必须已无 DELETE（否则以非零退出）。
-- 首次装机在迁移之前跑本脚本时该表还不存在、上面的 REVOKE 是空操作：这种状态下不能静默通过，
-- 必须显式告警要求「迁移完成后重跑」，否则默认权限会让迁移新建的表重新带上 DELETE。
DO $$
BEGIN
  IF to_regclass('public.signing_keys') IS NULL THEN
    RAISE WARNING 'signing_keys 尚不存在：本次未收紧其 DELETE 权限（迁移完成后请重跑本脚本）。';
  ELSIF has_table_privilege('panda_auth', 'public.signing_keys', 'DELETE') THEN
    RAISE EXCEPTION 'panda_auth still holds DELETE on public.signing_keys';
  END IF;
END
$$;
SQL

if [ -n "${PANDA_AUTH_HBA_FILE:-}" ]; then
  HBA_FILE="$PANDA_AUTH_HBA_FILE"
else
  HBA_FILE="$(postgres_psql -X -v ON_ERROR_STOP=1 -tA -c 'SHOW hba_file' | tr -d '[:space:]')"
fi
HBA_BACKUP="$(dirname "$HBA_FILE")/$(basename "$HBA_FILE").pre-panda-auth.$(date -u +%Y%m%d%H%M%S)"
TEMP_FILE="$(mktemp "${HBA_FILE}.XXXXXX")"
trap 'rm -f "$TEMP_FILE"' EXIT
cp -a "$HBA_FILE" "$HBA_BACKUP"

HBA_HOSTS="${PANDA_AUTH_HBA_HOSTS:-127.0.0.1/32 ::1/128}"
read -r -a HBA_HOST_LIST <<< "$HBA_HOSTS"
HBA_RULES=(
  'local panda_auth panda_auth reject'
  'local panda_auth_migrator panda_auth_migrator reject'
)
for hba_host in "${HBA_HOST_LIST[@]}"; do
  if [[ ! "$hba_host" =~ ^[0-9A-Fa-f:./]+$ ]]; then
    echo "Invalid PANDA_AUTH_HBA_HOSTS entry: $hba_host" >&2
    exit 1
  fi
  HBA_RULES+=(
    "host panda_auth panda_auth $hba_host scram-sha-256"
    "host panda_auth panda_auth_migrator $hba_host scram-sha-256"
  )
done
HBA_RULES+=(
  'host panda_auth panda_auth 0.0.0.0/0 reject'
  'host panda_auth panda_auth ::/0 reject'
  'host panda_auth panda_auth_migrator 0.0.0.0/0 reject'
  'host panda_auth panda_auth_migrator ::/0 reject'
)

# Replace only our managed block. Explicit rejects precede any broad host rules,
# so neither database credential can be used from a non-loopback address.
awk '
  /^# BEGIN PANDAAUTH MANAGED RULES$/ { skip = 1; next }
  /^# END PANDAAUTH MANAGED RULES$/ { skip = 0; next }
  !skip { print }
' "$HBA_FILE" > "$TEMP_FILE"
{
  echo '# BEGIN PANDAAUTH MANAGED RULES'
  printf '%s\n' "${HBA_RULES[@]}"
  echo '# END PANDAAUTH MANAGED RULES'
  cat "$TEMP_FILE"
} > "${TEMP_FILE}.new"
mv "${TEMP_FILE}.new" "$TEMP_FILE"
chown --reference="$HBA_FILE" "$TEMP_FILE"
chmod --reference="$HBA_FILE" "$TEMP_FILE"
mv "$TEMP_FILE" "$HBA_FILE"
trap - EXIT

if ! postgres_psql -X -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()' >/dev/null \
  || postgres_psql -X -v ON_ERROR_STOP=1 -tA -c \
    "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL" | grep -vq '^0$'; then
  cp -a "$HBA_BACKUP" "$HBA_FILE"
  postgres_psql -X -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()' >/dev/null || true
  echo "PostgreSQL rejected the HBA configuration; restored the backup at $HBA_BACKUP." >&2
  exit 1
fi

HBA_RULES_OK="t"
for rule in "${HBA_RULES[@]}"; do
  if ! grep -Fxq "$rule" "$HBA_FILE"; then HBA_RULES_OK="f"; break; fi
done
if [ "$HBA_RULES_OK" = "t" ] && postgres_psql -X -v ON_ERROR_STOP=1 -tA -c \
  "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL" | grep -vq '^0$'; then
  HBA_RULES_OK="f"
fi
if [ "$HBA_RULES_OK" != "t" ]; then
  cp -a "$HBA_BACKUP" "$HBA_FILE"
  postgres_psql -X -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()' >/dev/null || true
  echo "Required database/role HBA rules were not loaded; restored the backup at $HBA_BACKUP." >&2
  exit 1
fi

if ! PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U panda_auth -d panda_auth -X -v ON_ERROR_STOP=1 -tA -c 'SELECT 1' >/dev/null; then
  echo "panda_auth TCP login failed. Ensure the password entered above matches DB_PASSWORD." >&2
  exit 1
fi

echo "Database roles, least-privilege grants, and loopback-only SCRAM rules are configured."
echo "Add DB_MIGRATOR_PASSWORD to $SECRET_FILE (mode 0600) using the password just entered."
echo "Before release, verify DB_MIGRATOR_PASSWORD and use the one-off migration container."

# 显式报告签名密钥权限状态：首次装机（迁移前）该表还不存在，上面的 REVOKE 是空操作，
# 必须让运维一眼看到「还没收紧、迁移后要重跑」，而不是把静默通过当成已完成。
SIGNING_KEYS_STATE="$(postgres_psql -X -v ON_ERROR_STOP=1 -tA -d panda_auth -c \
  "SELECT CASE
     WHEN to_regclass('public.signing_keys') IS NULL THEN 'absent'
     WHEN has_table_privilege('panda_auth', 'public.signing_keys', 'DELETE') THEN 'still-delete'
     ELSE 'hardened'
   END" | tr -d '[:space:]')"
case "$SIGNING_KEYS_STATE" in
  hardened)
    echo "signing_keys 的 DELETE 权限已收紧并自检通过（运行角色仅 SELECT/INSERT/UPDATE）。"
    ;;
  absent)
    echo "未完成：signing_keys 尚不存在（本机还没迁移），本次没有收紧它的 DELETE 权限。" >&2
    echo "        迁移完成后请重跑本脚本：默认权限会给新建的 signing_keys 带上 DELETE。" >&2
    echo "        重跑命令：sudo bash $0" >&2
    ;;
  *)
    echo "签名密钥权限自检未通过（状态：$SIGNING_KEYS_STATE），请检查 panda_auth 对 signing_keys 的授权。" >&2
    exit 1
    ;;
esac
