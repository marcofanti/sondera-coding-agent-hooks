#!/usr/bin/env bash
# Shared helpers for the Sondera e2e scripts. Source this; do not execute.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="${SERVER_BIN:-$REPO_ROOT/target/debug/sondera-harness-server}"
CLAUDE_BIN="${CLAUDE_BIN:-$REPO_ROOT/target/debug/sondera-claude}"
CURSOR_BIN="${CURSOR_BIN:-$REPO_ROOT/target/debug/sondera-cursor}"
GEMINI_BIN="${GEMINI_BIN:-$REPO_ROOT/target/debug/sondera-gemini}"
ADMIN_URL="${ADMIN_URL:-http://localhost:9090}"
SOCKET_PATH="${SOCKET_PATH:-$HOME/.sondera/sondera-harness.sock}"

PASS_COUNT=0
FAIL_COUNT=0

green() { printf '\033[32m%s\033[0m' "$1"; }
red() { printf '\033[31m%s\033[0m' "$1"; }

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '  %s %s\n' "$(green PASS)" "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '  %s %s\n' "$(red FAIL)" "$1"
}

# assert_contains <label> <haystack> <needle>
assert_contains() {
  if printf '%s' "$2" | grep -qF "$3"; then
    pass "$1"
  else
    fail "$1 — expected to contain '$3', got: $2"
  fi
}

# assert_eq <label> <actual> <expected>
assert_eq() {
  if [ "$2" = "$3" ]; then
    pass "$1"
  else
    fail "$1 — expected '$3', got '$2'"
  fi
}

summary() {
  printf '\n==== %s: %s passed, %s failed ====\n' \
    "${1:-e2e}" "$(green "$PASS_COUNT")" "$([ "$FAIL_COUNT" -eq 0 ] && printf '%s' "$FAIL_COUNT" || red "$FAIL_COUNT")"
  [ "$FAIL_COUNT" -eq 0 ]
}

# Substitute the fixture placeholders with a live session id + cwd.
render_fixture() {
  local file="$1" sid="${2:-e2e-session}" cwd="${3:-/tmp}"
  sed -e "s|__SID__|$sid|g" -e "s|__CWD__|$cwd|g" "$file"
}

wait_for_admin() {
  local tries=0
  until curl -s -o /dev/null "$ADMIN_URL/api/escalations" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -gt 30 ] && {
      echo "admin API never came up at $ADMIN_URL" >&2
      return 1
    }
    sleep 0.5
  done
}

start_harness() {
  # start_harness <engine> [extra args...]
  local engine="$1"
  shift
  # Ensure no prior harness holds the socket / admin port, even one started by
  # another shell in this campaign.
  pkill -f 'sondera-harness-server' 2>/dev/null || true
  local waited=0
  while pgrep -f 'sondera-harness-server' >/dev/null 2>&1; do
    sleep 0.3
    waited=$((waited + 1))
    [ "$waited" -gt 20 ] && break
  done
  rm -f "$SOCKET_PATH"
  "$SERVER_BIN" --policy-engine "$engine" --socket "$SOCKET_PATH" \
    --admin-port 9090 "$@" >/tmp/sondera-e2e-harness.log 2>&1 &
  HARNESS_PID=$!
  wait_for_admin
}

stop_harness() {
  pkill -f 'sondera-harness-server' 2>/dev/null || true
  wait "${HARNESS_PID:-}" 2>/dev/null || true
  HARNESS_PID=""
  local waited=0
  while pgrep -f 'sondera-harness-server' >/dev/null 2>&1; do
    sleep 0.3
    waited=$((waited + 1))
    [ "$waited" -gt 20 ] && break
  done
}
