#!/usr/bin/env bash
# Run the UNGATED PydanticAI agent live, with the API key resolved from
# 1Password. Governance here comes only from Claude Code hooks IF you launch
# this from a hooked Claude Code session (project scope) — the agent's own
# tools are not adjudicated. For tool-level governance use run_gated.sh.
#
# Usage:  ./run.sh "list the files in the workspace and summarize them"
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT="${1:-Create a file notes.txt with three bullet points about Cedar policies, then read it back.}"

[ -f "$DIR/.env" ] || {
  echo "Missing $DIR/.env — copy .env.example and set your op:// reference." >&2
  exit 1
}
command -v op >/dev/null || { echo "1Password CLI 'op' not found on PATH." >&2; exit 1; }
command -v uv >/dev/null || { echo "'uv' not found on PATH." >&2; exit 1; }

op run --env-file="$DIR/.env" -- \
  uv run --project "$DIR" python "$DIR/pydantic-ai-read-write-edit.py" <<<"$PROMPT"
