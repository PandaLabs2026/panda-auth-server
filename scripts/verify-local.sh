#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

meta="$HOME/dev/pandalabs/meta"
if [[ "${PANDALABS_MANAGED_EXECUTION:-}" == "1" && -n "${PANDALABS_BASELINE_ID:-}" ]]; then
  capacity_mode=(--outer-capacity-admitted)
else
  capacity_mode=(--default)
fi
capacity_paths=(
  --path "$root"
  --path "$root/src"
  --path "$root/tests"
  --path "$(dirname "$root")/panda-auth-share"
  --path "${NUGET_PACKAGES:-$HOME/.nuget/packages}"
  --path "$HOME/.local/share/NuGet/http-cache"
  --path "${DOTNET_CLI_HOME:-$HOME/.dotnet}"
)
python3 -I -B "$meta/scripts/capacity_preflight.py" "${capacity_mode[@]}" "${capacity_paths[@]}"

dotnet restore PandaAuth.Server.slnx
dotnet build PandaAuth.Server.slnx --no-restore
dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj --no-restore

git diff --check
echo "panda-auth-server local verification passed."
