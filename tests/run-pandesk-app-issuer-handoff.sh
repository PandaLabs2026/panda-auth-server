#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $(uname -s) == Linux && $(id -u) != 0 ]]
task_root=$(realpath -e -- "${PANDALABS_TEMP_ROOT:?Use the registered pandalabs-env Docker mode}")
[[ -O "$task_root" && $(stat -c %a -- "$task_root") == 700 ]]
[[ -z ${DOCKER_HOST:-} || $DOCKER_HOST == unix:///var/run/docker.sock ]]
[[ $(docker context show) == default ]]
[[ $(docker context inspect default --format '{{(index .Endpoints "docker").Host}}') == unix:///var/run/docker.sock ]]
[[ $(docker info --format '{{.Name}}') == "$(hostname)" ]]
listeners=$(ss -H -ltn 'sport = :43823')
if [[ -n $listeners ]]; then
    printf 'Disposable PostgreSQL port 43823 is already in use.\n' >&2
    exit 1
fi

image=postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
docker image inspect "$image" --format 'PostgreSQL image {{.Id}}'
unset PANDA_AUTH_TEST_POSTGRES PANDA_AUTH_TEST_SHARED_POSTGRES
export PANDALABS_TEMP_ROOT="$task_root" PANDA_AUTH_PANDESK_APP_HANDOFF_DIR
PANDA_AUTH_PANDESK_APP_HANDOFF_DIR=$(mktemp -d "$task_root/pandesk-app-handoff.XXXXXXXX")
handoff=$PANDA_AUTH_PANDESK_APP_HANDOFF_DIR
name=$(basename "$handoff" | tr '[:upper:]' '[:lower:]' | tr . -)
network=
cleanup() {
    local result=$?
    trap - EXIT
    local container
    if container=$(docker ps -aq --filter "label=pandalabs.task=$name"); then
        if [[ -n $container ]]; then docker rm -f "$container" >/dev/null || result=1; fi
    else
        result=1
    fi
    if [[ -n $network ]]; then docker network rm "$network" >/dev/null || result=1; fi
    if ! rm -f -- "$handoff"/{handoff.json,stop,t9876.{pem,totp,login.json,introspection.json},t9877.{pem,totp,login.json,introspection.json}}{,.tmp}; then
        result=1
    fi
    if ! rmdir -- "$handoff"; then result=1; fi
    printf 'Fixture cleanup exit %s\n' "$result"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export POSTGRES_PASSWORD
POSTGRES_PASSWORD=$(openssl rand -hex 32)
network=$(docker network create --label "pandalabs.task=$name" "$name")
container=$(docker run -d --pull never --name "$name" --label "pandalabs.task=$name" \
    --network "$network" -p 127.0.0.1:43823:5432 --tmpfs /var/lib/postgresql:rw,size=1g \
    -e POSTGRES_PASSWORD "$image")
for attempt in {1..45}; do
    if docker exec "$container" pg_isready -q -h 127.0.0.1; then break; fi
    sleep 1
done
docker exec "$container" pg_isready -q -h 127.0.0.1
export PANDA_AUTH_TEST_POSTGRES="Host=127.0.0.1;Port=43823;Database=postgres;Username=postgres;Password=$POSTGRES_PASSWORD"
unset POSTGRES_PASSWORD

printf 'Handoff will be ready at %s/handoff.json\n' "$handoff"
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj --no-restore \
    -p:NuGetPackageRoot="${NUGET_PACKAGES%/}/" --filter 'FullyQualifiedName~PandeskAppIssuerHandoffTests' \
    --results-directory "$task_root" --logger "trx;LogFileName=$name.trx"
