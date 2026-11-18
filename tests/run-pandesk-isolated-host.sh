#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 || $(uname -s) != Linux || $(id -u) == 0 ]]; then
    printf 'Usage (non-root Linux): bash tests/run-pandesk-isolated-host.sh <native PostgreSQL 18 package root>\n' >&2
    exit 2
fi

task_root=${PANDALABS_TEMP_ROOT:?Use the registered pandalabs-dev entry point}
task_root=$(realpath -e -- "$task_root")
[[ -O "$task_root" && $(stat -c %a -- "$task_root") == 700 ]]
export PANDALABS_TEMP_ROOT="$task_root"
package=$(realpath -e -- "$1")
pg="$package/usr/lib/postgresql/18/bin"
export LD_LIBRARY_PATH="$package/usr/lib/x86_64-linux-gnu"
for binary in initdb pg_ctl; do
    [[ -x "$pg/$binary" ]]
done
psql="$pg/psql"
if [[ ! -x "$psql" ]]; then
    psql=/usr/lib/postgresql/18/bin/psql
fi
[[ -x "$psql" ]]
if [[ -n "$(ss -Hln 'sport = :43823')" ]]; then
    printf 'Disposable PostgreSQL port 43823 is already in use.\n' >&2
    exit 1
fi
unset PANDA_AUTH_TEST_POSTGRES PANDA_AUTH_TEST_SHARED_POSTGRES
export NUGET_PACKAGES="${NUGET_PACKAGES%/}/"

database_root=$(mktemp -d "$task_root/pandesk-pg.XXXXXX")
cleanup() {
    local result=$?
    if [[ -f "$database_root/db/postmaster.pid" ]]; then
        "$pg/pg_ctl" -D "$database_root/db" -w -m fast stop > "$database_root/stop.log" 2>&1 || result=1
    fi
    if [[ -n ${handoff_dir:-} ]]; then
        rm -f -- "$handoff_dir"/{handoff.json,t9841.pem,t9842.pem,t9841.totp,t9842.totp}{,.tmp}
    fi
    return "$result"
}
trap cleanup EXIT
mkdir "$database_root/socket"
printf 'PostgreSQL logs are in %s\n' "$database_root"
"$pg/initdb" -D "$database_root/db" -L "$package/usr/share/postgresql/18" \
    --auth-local=trust --auth-host=scram-sha-256 --encoding=UTF8 --no-locale > "$database_root/init.log" 2>&1
"$pg/pg_ctl" -D "$database_root/db" -l "$database_root/postgres.log" -w -t 20 \
    -o "-c listen_addresses=127.0.0.1 -c unix_socket_directories='$database_root/socket' -c port=43823 -c shared_buffers=64MB -c io_method=worker" start
admin=("$psql" -XqtA -h "$database_root/socket" -p 43823 -U "$(id -un)" -d postgres -v ON_ERROR_STOP=1)
[[ $("${admin[@]}" -c 'SHOW data_directory') == "$database_root/db" ]]
[[ $("${admin[@]}" -c 'SHOW listen_addresses') == 127.0.0.1 ]]
password=$(openssl rand -hex 25)
printf "CREATE ROLE pandesk_fixture LOGIN CREATEDB PASSWORD '%s';\n" "$password" | "${admin[@]}" >/dev/null
export PANDA_AUTH_TEST_POSTGRES="Host=127.0.0.1;Port=43823;Database=postgres;Username=pandesk_fixture;Password=$password"
unset password

handoff_dir=$(mktemp -d "$task_root/pandesk-handoff.XXXXXX")
export PANDA_AUTH_PANDESK_HANDOFF_DIR="$handoff_dir"
printf 'Handoff files will be ready at %s/handoff.json\n' "$handoff_dir"
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj -m:1 --no-restore \
    -p:NuGetPackageRoot="$NUGET_PACKAGES" --filter 'FullyQualifiedName~PandeskIsolatedHostTests'
