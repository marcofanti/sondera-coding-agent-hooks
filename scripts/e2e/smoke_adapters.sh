#!/usr/bin/env bash
# Drive each hook adapter binary with fixtures and assert the decision.
# Requires a running harness (cedarling engine). Run via run_all.sh or standalone.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Self-contained: (re)start a cedarling harness and tear it down on exit.
start_harness cedarling --otel --otel-metrics --otel-endpoint "${OTEL_ENDPOINT:-http://localhost:4317}"
trap stop_harness EXIT

FIX="$REPO_ROOT/examples"
SID="adapter-smoke"

echo "== Claude adapter =="
out="$(render_fixture "$FIX/claude_code_hooks/fixtures/preToolUse-allow.json" "$SID" /tmp | "$CLAUDE_BIN" pre-tool-use 2>/dev/null)"
assert_eq "claude allow serializes to {}" "$out" "{}"

out="$(render_fixture "$FIX/claude_code_hooks/fixtures/preToolUse-deny.json" "$SID" /tmp | "$CLAUDE_BIN" pre-tool-use 2>/dev/null)"
assert_contains "claude deny → permissionDecision deny" "$out" '"permissionDecision":"deny"'
assert_contains "claude deny cites a policy id" "$out" 'forbid-rm'

out="$(render_fixture "$FIX/claude_code_hooks/fixtures/sessionStart.json" "$SID" /tmp | "$CLAUDE_BIN" session-start 2>/dev/null)"
assert_contains "claude session-start returns hookSpecificOutput" "$out" 'SessionStart'

echo "== Cursor adapter =="
out="$(render_fixture "$FIX/cursor_hooks/fixtures/beforeShellExecution-allow.json" "$SID" /tmp | "$CURSOR_BIN" before-shell-execution 2>/dev/null)"
assert_contains "cursor allow → permission allow" "$out" '"permission":"allow"'

set +e
out="$(render_fixture "$FIX/cursor_hooks/fixtures/beforeShellExecution-deny.json" "$SID" /tmp | "$CURSOR_BIN" before-shell-execution 2>/dev/null)"
code=$?
set -e
assert_contains "cursor deny → permission deny" "$out" '"permission":"deny"'
assert_eq "cursor deny exits 2" "$code" "2"

echo "== Gemini adapter =="
out="$(render_fixture "$FIX/gemini_cli_hooks/fixtures/beforeTool-allow.json" "$SID" /tmp | "$GEMINI_BIN" before-tool 2>/dev/null)"
assert_contains "gemini allow → decision allow" "$out" '"decision":"allow"'

out="$(render_fixture "$FIX/gemini_cli_hooks/fixtures/beforeTool-deny.json" "$SID" /tmp | "$GEMINI_BIN" before-tool 2>/dev/null)"
assert_contains "gemini deny → decision deny" "$out" '"decision":"deny"'

summary "adapters"
