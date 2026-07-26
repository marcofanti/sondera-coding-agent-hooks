#!/usr/bin/env bash
# Deterministic smoke test for the read/write/shell agent — no model call, no
# tokens spent. Proves the plumbing and BOTH governance layers:
#
#   Layer 1 (Claude Code hooks, project scope): the command that LAUNCHES the
#     agent is adjudicated by sondera-claude's PreToolUse hook. A project-scoped
#     install is generated into a throwaway dir and its shape asserted; a benign
#     launch is Allowed and a launch tampered with `rm -rf /` is Denied.
#
#   Layer 2 (PolicyGate on the agent's own tools): the read/write/shell actions
#     the agent would take are adjudicated directly against the harness — a
#     clean write is Allowed, reading a private key and `rm -rf /` are Denied.
#
# Requires a running harness on :9090. Does NOT require op/network/uv.
#
#   sondera-harness-server --policy-engine cedarling --admin-port 9090 -v
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
CLAUDE_BIN="${CLAUDE_BIN:-$REPO_ROOT/target/debug/sondera-claude}"
ADMIN_URL="${SONDERA_ADMIN_URL:-http://localhost:9090}"
PY="${PY:-$REPO_ROOT/examples/gated_file_agent/.venv/bin/python}"
[ -x "$PY" ] || PY="python3"

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
contains() { printf '%s' "$2" | grep -qF "$3" && pass "$1" || fail "$1 — got: $2"; }

command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }
curl -s -o /dev/null "$ADMIN_URL/api/escalations" || {
  echo "Harness not reachable at $ADMIN_URL — start it with --policy-engine cedarling --admin-port 9090" >&2
  exit 1
}

# ── Layer 1: project-scoped Claude Code hook install + launch adjudication ────
echo "== Layer 1: Claude Code project hooks (launch command) =="
TMP_PROJ="$(mktemp -d "${TMPDIR:-/tmp}/rwsa-proj.XXXXXX")"
trap 'rm -rf "$TMP_PROJ"' EXIT
( cd "$TMP_PROJ" && "$CLAUDE_BIN" install --project >/dev/null 2>&1 )
settings="$TMP_PROJ/.claude/settings.json"
if [ -f "$settings" ]; then
  pass "install --project wrote .claude/settings.json"
  contains "project settings register a PreToolUse hook" "$(cat "$settings")" '"PreToolUse"'
  contains "hook command points at sondera-claude"       "$(cat "$settings")" 'sondera-claude'
else
  fail "install --project did not write .claude/settings.json"
fi

pretool() { # command → hook JSON ({} on allow, permissionDecision on deny)
  printf '{"session_id":"rwsa","transcript_path":"/tmp/t","cwd":"%s","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%s}}' \
    "$DIR" "$("$PY" -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1")" \
    | "$CLAUDE_BIN" pre-tool-use 2>/dev/null
}

# Plain launch (API key already in the environment) — benign, Allowed.
plain="uv run --project $DIR python $DIR/pydantic-ai-read-write-edit.py"
out="$(pretool "$plain")"
[ "$out" = "{}" ] && pass "plain uv-run launch is Allowed ({})" || fail "plain launch not allowed: $out"

# Inline 1Password resolution references .env, which the harness treats as
# credential access — so this launch form is Denied. A real governance signal,
# not a bug: to launch under project hooks, resolve the key out-of-band (op run
# in a separate step) rather than reading a credential file in the tool command.
oprun="op run --env-file=$DIR/.env -- $plain"
out="$(pretool "$oprun")"
contains "op --env-file launch flagged credential-access" "$out" '"permissionDecision":"deny"'
contains "  ↳ cites forbid-shell-credential-access" "$out" "forbid-shell-credential-access"

# Tampered launch chaining a destructive command — Denied.
tampered="$plain && rm -$(printf r)f /"
out="$(pretool "$tampered")"
contains "tampered launch (rm -rf) is Denied" "$out" '"permissionDecision":"deny"'

# ── Layer 2: PolicyGate on the agent's own tools ──────────────────────────────
echo "== Layer 2: PolicyGate on agent tools =="
gate_decision() { # kind arg1 [arg2] → "<decision>|<policy-ids>"
  "$PY" - "$ADMIN_URL" "$@" <<'PY'
import sys
from sondera import Action, PolicyGate
admin = sys.argv[1]
kind = sys.argv[2]
gate = PolicyGate(admin_url=admin, default_agent_id="read-write-shell-agent",
                  default_provider_id="pydantic-ai")
if kind == "read":
    action = Action.read_file(sys.argv[3])
elif kind == "write":
    action = Action.write_file(sys.argv[3], sys.argv[4])
elif kind == "shell":
    action = Action.shell(sys.argv[3], *sys.argv[4:])
else:
    raise SystemExit(f"unknown kind {kind}")
with gate.trajectory(trajectory_id="rwsa-smoke") as t:
    d = t.check(action)
ids = ",".join(a.get("policy_id", "") for a in (d.annotations or []))
print(f"{d.decision}|{ids}")
PY
}

r="$(gate_decision write notes.txt 'hello world')"
[ "${r%%|*}" = "Allow" ] && pass "clean write_file → Allow" || fail "clean write not allowed: $r"

r="$(gate_decision read secrets.pem)"
[ "${r%%|*}" = "Deny" ] && pass "read private key → Deny" || fail "private key read not denied: $r"
contains "  ↳ cites forbid-private-key-read" "$r" "forbid-private-key-read"

r="$(gate_decision shell rm "-$(printf r)f" /)"
[ "${r%%|*}" = "Deny" ] && pass "destructive shell → Deny" || fail "rm -rf not denied: $r"

printf '\n==== read-write-shell-agent smoke: \033[32m%s\033[0m passed, %s failed ====\n' \
  "$PASS" "$([ "$FAIL" -eq 0 ] && echo "$FAIL" || printf '\033[31m%s\033[0m' "$FAIL")"
[ "$FAIL" -eq 0 ]
