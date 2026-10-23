#!/usr/bin/env bash
# Clear ALL SkyForge data (projects, scans, findings, fix branches, artifacts, uploaded AWS dumps, audit log).
# Settings, .env and bundled fixtures are kept.
#
#   scripts/reset_data.sh                       # server stopped: wipes the local database + data folders
#   SKYFORGE_TOKEN=<admin token> scripts/reset_data.sh   # server running: resets through the API
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
URL="${SKYFORGE_URL:-http://127.0.0.1:8000}"

if curl -fsS -o /dev/null --max-time 2 "$URL/api/v1/health" 2>/dev/null; then
  if [[ -z "${SKYFORGE_TOKEN:-}" ]]; then
    echo "SkyForge is running at $URL. Either stop it first, or set SKYFORGE_TOKEN to an admin API token." >&2
    exit 1
  fi
  read -r -p "Delete ALL SkyForge data on $URL? Type 'yes': " answer
  [[ "$answer" == "yes" ]] || { echo "Aborted."; exit 1; }
  curl -fsS -X POST "$URL/api/v1/admin/reset" \
    -H "Authorization: Bearer $SKYFORGE_TOKEN" -H "Content-Type: application/json" \
    -d '{"confirm": "DELETE ALL DATA"}'
  echo
else
  read -r -p "Delete ALL SkyForge data in $ROOT/data? Type 'yes': " answer
  [[ "$answer" == "yes" ]] || { echo "Aborted."; exit 1; }
  cd "$ROOT/backend" && ../.venv/bin/python -m app.services.reset --yes
fi
