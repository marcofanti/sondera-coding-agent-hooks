#!/usr/bin/env bash
# Inspect / shadow mode: the InspectPolicyEngine runs the real Cedar evaluation,
# emits telemetry, then overrides the decision.
#   --inspect-mode allow  → always Allow, but the would-be-deny policy ids are
#                           carried through in the response annotations (audit).
#   --inspect-mode prompt → always Escalate (every action awaits approval).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

trap stop_harness EXIT
PY="$REPO_ROOT/examples/gated_file_agent/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

# adjudicate_file <op> <path> → prints "<decision>|<csv-policy-ids>"
adjudicate_file() {
  "$PY" - "$1" "$2" "$ADMIN_URL" <<'PY'
import sys, uuid, time, requests
op, path, admin = sys.argv[1:4]
ev = {"event_id": str(uuid.uuid4()), "trajectory_id": "inspect",
      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "agent": {"id": "gated-file-agent", "provider_id": "python"},
      "actor": {"id": "gated-file-agent", "actor_type": "Agent"},
      "causality": {"correlation_id": "inspect", "causation_id": None, "parent_id": None},
      "event": {"category": "Action", "payload": {"type": "FileOperation",
                "data": {"call_id": "c", "operation": op, "path": path, "content": None}}},
      "raw": None}
r = requests.post(f"{admin}/api/adjudicate", json=ev, timeout=10).json()
ids = ",".join(a.get("policy_id", "") for a in r.get("annotations", []))
print(f"{r['decision']}|{ids}")
PY
}

echo "== Inspect allow (shadow/audit) =="
start_harness inspect --inspect-mode allow \
  --otel --otel-metrics --otel-endpoint "${OTEL_ENDPOINT:-http://localhost:4317}"

result="$(adjudicate_file Read server.pem)"
decision="${result%%|*}"
policies="${result#*|}"
assert_eq "shadow: forbidden read overridden to Allow" "$decision" "Allow"
assert_contains "shadow: would-be-deny policy recorded" "$policies" "forbid-private-key-read"

result="$(adjudicate_file Read notes.md)"
assert_eq "shadow: clean read stays Allow" "${result%%|*}" "Allow"

echo "== Inspect prompt (approve-everything) =="
stop_harness
start_harness inspect --inspect-mode prompt

result="$(adjudicate_file Read notes.md)"
assert_eq "prompt: even a clean action escalates" "${result%%|*}" "Escalate"

summary "inspect"
