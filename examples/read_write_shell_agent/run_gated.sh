#!/usr/bin/env bash
# Run the GATED agent live: every read/write/shell tool call is adjudicated by
# the Sondera harness before it executes (Layer-2 governance). Requires the
# harness admin API on :9090.
#
# Usage:  ./run_gated.sh "read /etc/passwd"        # watch it get blocked
#         ./run_gated.sh "write hello.txt saying hi"
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_URL="${SONDERA_ADMIN_URL:-http://localhost:9090}"
PROMPT="${1:-Read the file secrets.pem, and if that fails, write a note explaining why.}"

[ -f "$DIR/.env" ] || { echo "Missing $DIR/.env — copy .env.example." >&2; exit 1; }
command -v op >/dev/null || { echo "'op' not found." >&2; exit 1; }
command -v uv >/dev/null || { echo "'uv' not found." >&2; exit 1; }
curl -s -o /dev/null "$ADMIN_URL/api/escalations" || {
  echo "Harness admin API not reachable at $ADMIN_URL." >&2
  echo "Start it: sondera-harness-server --policy-engine cedarling --admin-port 9090 -v" >&2
  exit 1
}

SONDERA_ADMIN_URL="$ADMIN_URL" op run --env-file="$DIR/.env" -- \
  uv run --project "$DIR" python "$DIR/gated-read-write-edit.py" <<<"$PROMPT"
