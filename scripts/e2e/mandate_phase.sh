#!/usr/bin/env bash
# Provision a per-agent identity with a signed mandate and test enforcement.
# Verifies: keygen/sign/verify round-trip, no-JWT → Deny, valid-JWT → Allow.
# NOTE: the async engine does NOT yet enforce the mandate policy subset — a
# read-only mandate still allows writes. This script asserts the presence gate
# and records the subset gap as a finding.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sondera-mandate.XXXXXX")"
cleanup() {
  stop_harness
  rm -rf "$WORK"
}
trap cleanup EXIT
PY="$REPO_ROOT/examples/gated_file_agent/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

echo "== Mandate keygen / sign / verify =="
"$CLAUDE_BIN" mandate keygen --signing-key "$WORK/sign.key" --verifying-key "$WORK/verify.key" >/dev/null 2>&1
assert_eq "signing key is 32 bytes" "$(wc -c <"$WORK/sign.key" | tr -d ' ')" "32"

cat >"$WORK/readonly.cedar" <<'CEDAR'
permit ( principal, action == Jans::Action::"read_file", resource );
CEDAR
"$CLAUDE_BIN" mandate sign --signing-key "$WORK/sign.key" --agent-id gated-file-agent \
  --policy "$WORK/readonly.cedar" --exp-secs 3600 >"$WORK/token.jwt" 2>/dev/null
JWT="$(cat "$WORK/token.jwt")"
verified="$("$CLAUDE_BIN" mandate verify --verifying-key "$WORK/verify.key" <"$WORK/token.jwt" 2>/dev/null)"
assert_contains "verify round-trips the agent id" "$verified" '"sub": "gated-file-agent"'

echo "== Restart harness with the mandate engine =="
stop_harness
start_harness mandate --mandate-pub-key "$WORK/verify.key"

adjudicate() {
  # adjudicate <op> <path> <jwt-or-empty>
  "$PY" - "$1" "$2" "$3" "$ADMIN_URL" <<'PY'
import json, sys, uuid, time, requests
op, path, jwt, admin = sys.argv[1:5]
raw = {"mandate_jwt": jwt} if jwt else None
ev = {"event_id": str(uuid.uuid4()), "trajectory_id": "tm",
      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "agent": {"id": "gated-file-agent", "provider_id": "python"},
      "actor": {"id": "gated-file-agent", "actor_type": "Agent"},
      "causality": {"correlation_id": "tm", "causation_id": None, "parent_id": None},
      "event": {"category": "Action", "payload": {"type": "FileOperation",
                "data": {"call_id": "c1", "operation": op, "path": path,
                         "content": None if op == "Read" else "x"}}},
      "raw": raw}
r = requests.post(f"{admin}/api/adjudicate", json=ev, timeout=10)
print(r.json()["decision"])
PY
}

assert_eq "no mandate JWT → Deny"        "$(adjudicate Read notes.md '')"    "Deny"
assert_eq "valid mandate + read → Allow" "$(adjudicate Read notes.md "$JWT")" "Allow"

# Subset gap: a read-only mandate SHOULD deny write. It currently Allows.
write_decision="$(adjudicate Write out.txt "$JWT")"
if [ "$write_decision" = "Deny" ]; then
  pass "read-only mandate denies write (subset enforced)"
else
  printf '  \033[33mFINDING\033[0m read-only mandate ALLOWS write (subset NOT enforced): got %s\n' "$write_decision"
fi

summary "mandate"
