#!/usr/bin/env bash
# Exercise the escalation lifecycle: an agent's send_email triggers an Escalate,
# an operator approves/denies out of band, and a third is left to time out.
# Requires a running harness with --admin-port and a short --escalation-ttl.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Self-contained: (re)start a cedarling harness and tear it down on exit.
start_harness cedarling --otel --otel-metrics --otel-endpoint "${OTEL_ENDPOINT:-http://localhost:4317}"
trap stop_harness EXIT

PY="$REPO_ROOT/examples/gated_file_agent/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

echo "== Escalation: approve =="
"$PY" - "$ADMIN_URL" approve <<'PY'
import sys, time, uuid, threading, requests
from sondera.gate import PolicyGate
from sondera.actions import Action
admin, action = sys.argv[1], sys.argv[2]
gate = PolicyGate(admin_url=admin)
with gate.trajectory(trajectory_id=str(uuid.uuid4())) as t:
    d = t.check(Action.send_email())
assert d.escalate, f"expected Escalate, got {d.decision}"
handle = gate.escalation_handle(d)
assert handle, "no escalation handle"

def decide():
    time.sleep(1.0)
    requests.post(f"{admin}/api/escalations/{d.escalation_id}/{action}",
                  json={"decided_by": "e2e"}, timeout=10)

threading.Thread(target=decide).start()
resolved = handle.wait(poll_interval=0.5, timeout=15)
expected = "Allow" if action == "approve" else "Deny"
assert resolved.decision == expected, f"{action}: expected {expected}, got {resolved.decision}"
print(f"OK approve→{resolved.decision}")
PY
pass "escalation approve → agent unblocks Allow"

echo "== Escalation: deny =="
"$PY" - "$ADMIN_URL" deny <<'PY'
import sys, time, uuid, threading, requests
from sondera.gate import PolicyGate
from sondera.actions import Action
admin, action = sys.argv[1], sys.argv[2]
gate = PolicyGate(admin_url=admin)
with gate.trajectory(trajectory_id=str(uuid.uuid4())) as t:
    d = t.check(Action.send_email())
handle = gate.escalation_handle(d)

def decide():
    time.sleep(1.0)
    requests.post(f"{admin}/api/escalations/{d.escalation_id}/{action}",
                  json={"decided_by": "e2e"}, timeout=10)

threading.Thread(target=decide).start()
resolved = handle.wait(poll_interval=0.5, timeout=15)
assert resolved.decision == "Deny", f"deny: expected Deny, got {resolved.decision}"
print("OK deny→Deny")
PY
pass "escalation deny → agent unblocks Deny"

echo "== Escalation: timeout (agent-observable) =="
# NOTE: the server TTL sweeper runs on a fixed 30s cadence (not derived from
# --escalation-ttl), so the record's status flips to timed_out up to 30s after
# it expires. The agent-observable contract — wait() returns Deny once its own
# deadline passes — is what we assert here.
"$PY" - "$ADMIN_URL" <<'PY'
import sys, uuid
from sondera.gate import PolicyGate
from sondera.actions import Action
admin = sys.argv[1]
gate = PolicyGate(admin_url=admin)
with gate.trajectory(trajectory_id=str(uuid.uuid4())) as t:
    d = t.check(Action.send_email())
handle = gate.escalation_handle(d)
resolved = handle.wait(poll_interval=0.5, timeout=8)  # no operator acts
assert resolved.decision == "Deny", f"timeout: expected Deny, got {resolved.decision}"
print("OK timeout→agent sees Deny")
PY
pass "escalation timeout → agent unblocks Deny"

summary "escalation"
