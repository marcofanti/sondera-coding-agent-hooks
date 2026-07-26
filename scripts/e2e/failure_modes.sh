#!/usr/bin/env bash
# With the harness STOPPED, confirm each adapter's fail-open vs fail-closed
# posture. Documents the inconsistency rather than asserting one policy.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Ensure nothing is listening.
pkill -f 'sondera-harness-server' 2>/dev/null || true
sleep 1
rm -f "$SOCKET_PATH"

FIX="$REPO_ROOT/examples"
SID="failure-mode"

echo "Harness is DOWN. Piping a PreToolUse event into each adapter."
echo

run_adapter() {
  # run_adapter <label> <bin> <subcommand> <fixture>
  local label="$1" bin="$2" sub="$3" fixture="$4"
  set +e
  local code
  render_fixture "$fixture" "$SID" /tmp | "$bin" "$sub" >/dev/null 2>&1
  code=$?
  set -e
  printf '  %-8s exit=%s posture=%s\n' "$label" "$code" \
    "$([ "$code" -ge 2 ] && echo FAIL-CLOSED || echo FAIL-OPEN)"
}

run_adapter claude "$CLAUDE_BIN" pre-tool-use \
  "$FIX/claude_code_hooks/fixtures/preToolUse-allow.json"
run_adapter cursor "$CURSOR_BIN" before-shell-execution \
  "$FIX/cursor_hooks/fixtures/beforeShellExecution-allow.json"
run_adapter gemini "$GEMINI_BIN" before-tool \
  "$FIX/gemini_cli_hooks/fixtures/beforeTool-allow.json"

cat <<'NOTE'

Expected (as of this campaign):
  claude  → exit 1  FAIL-OPEN   (Claude Code treats non-zero-but-not-2 as non-blocking)
  cursor  → exit 1  FAIL-OPEN   (policy denies use exit 2; connection errors bubble to 1)
  gemini  → exit 2  FAIL-CLOSED (explicit "any pipeline error aborts the action")

Finding: fail-open/fail-closed is NOT uniform across adapters. A deployment that
relies on the harness being up will silently run unmonitored under claude/cursor
if the server is down. See docs/e2e-runbook.md §Findings.
NOTE
