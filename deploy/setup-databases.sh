#!/usr/bin/env bash
# Configure the local PostgreSQL roles and least-privilege access for PandaAuth.
# Run with sudo. Passwords are entered through psql's hidden interactive prompt.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with: sudo bash $0" >&2
  exit 1
fi

command -v psql >/dev/null || { echo "psql is required." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required to read the env file safely." >&2; exit 1; }

SECRET_FILE=/home/jiayuhu/.config/panda-auth/panda-auth.env
if [ ! -f "$SECRET_FILE" ] || [ ! -r "$SECRET_FILE" ]; then
  echo "Missing or unreadable $SECRET_FILE; create it with mode 0600 first." >&2
  exit 1
fi
JIAYUHU_UID="$(id -u jiayuhu)"
SECRET_UID="$(stat -c '%u' "$SECRET_FILE")"
SECRET_MODE="$(stat -c '%a' "$SECRET_FILE")"
if [ "$SECRET_UID" != "$JIAYUHU_UID" ] || [ "$SECRET_MODE" != "600" ]; then
  echo "$SECRET_FILE must be owned by jiayuhu and have mode 0600." >&2
  exit 1
fi

PG_VERSION_NUM="$(sudo -u postgres psql -X -v ON_ERROR_STOP=1 -tA -c 'SHOW server_version_num' | tr -d '[:space:]')"
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

sudo -u postgres psql -X -v ON_ERROR_STOP=1 <<'SQL'
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
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c '\password panda_auth'
echo "Set a separate strong password for panda_auth_migrator."
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c '\password panda_auth_migrator'

sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d panda_auth <<'SQL'
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
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM panda_auth;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, panda_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE panda_auth_migrator IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO panda_auth;
SQL

HBA_FILE="$(sudo -u postgres psql -X -v ON_ERROR_STOP=1 -tA -c 'SHOW hba_file' | tr -d '[:space:]')"
HBA_BACKUP="$(dirname "$HBA_FILE")/$(basename "$HBA_FILE").pre-panda-auth.$(date -u +%Y%m%d%H%M%S)"
TEMP_FILE="$(mktemp "${HBA_FILE}.XXXXXX")"
trap 'rm -f "$TEMP_FILE"' EXIT
cp -a "$HBA_FILE" "$HBA_BACKUP"

# Replace only our managed block. Explicit rejects precede any broad host rules,
# so neither database credential can be used from a non-loopback address.
awk '
  /^# BEGIN PANDAAUTH MANAGED RULES$/ { skip = 1; next }
  /^# END PANDAAUTH MANAGED RULES$/ { skip = 0; next }
  !skip { print }
' "$HBA_FILE" > "$TEMP_FILE"
{
  cat <<'HBA'
# BEGIN PANDAAUTH MANAGED RULES
local panda_auth panda_auth reject
local panda_auth_migrator panda_auth reject
host panda_auth panda_auth 127.0.0.1/32 scram-sha-256
host panda_auth panda_auth ::1/128 scram-sha-256
host panda_auth_migrator panda_auth 127.0.0.1/32 scram-sha-256
host panda_auth_migrator panda_auth ::1/128 scram-sha-256
host panda_auth panda_auth 0.0.0.0/0 reject
host panda_auth panda_auth ::/0 reject
host panda_auth_migrator panda_auth 0.0.0.0/0 reject
host panda_auth_migrator panda_auth ::/0 reject
# END PANDAAUTH MANAGED RULES
HBA
  cat "$TEMP_FILE"
} > "${TEMP_FILE}.new"
mv "${TEMP_FILE}.new" "$TEMP_FILE"
chown --reference="$HBA_FILE" "$TEMP_FILE"
chmod --reference="$HBA_FILE" "$TEMP_FILE"
mv "$TEMP_FILE" "$HBA_FILE"
trap - EXIT

if ! sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()' >/dev/null \
  || sudo -u postgres psql -X -v ON_ERROR_STOP=1 -tA -c \
    "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL" | grep -vq '^0$'; then
  cp -a "$HBA_BACKUP" "$HBA_FILE"
  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()' >/dev/null || true
  echo "PostgreSQL rejected the HBA configuration; restored the backup at $HBA_BACKUP." >&2
  exit 1
fi

if ! PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U panda_auth -d panda_auth -X -v ON_ERROR_STOP=1 -tA -c 'SELECT 1' >/dev/null; then
  echo "panda_auth TCP login failed. Ensure the password entered above matches DB_PASSWORD." >&2
  exit 1
fi

echo "Database roles, least-privilege grants, and loopback-only SCRAM rules are configured."
echo "Add DB_MIGRATOR_PASSWORD to $SECRET_FILE (mode 0600) using the password just entered."
echo "Before release, verify DB_MIGRATOR_PASSWORD and use the one-off migration container."
