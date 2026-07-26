#!/usr/bin/env bash
# Agent Bill of Materials: project a trajectory's event stream into a CycloneDX
# document and read it back via the HTTP endpoints and the sondera-claude CLI.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

start_harness cedarling
trap stop_harness EXIT
PY="$REPO_ROOT/examples/gated_file_agent/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

TRAJ="agbom-e2e-$$"

echo "== Generate a varied trajectory =="
"$PY" - "$TRAJ" "$ADMIN_URL" <<'PY'
import sys, uuid, time, requests
traj, admin = sys.argv[1], sys.argv[2]
def send(payload):
    ev = {"event_id": str(uuid.uuid4()), "trajectory_id": traj,
          "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
          "agent": {"id": "bom-agent", "provider_id": "python"},
          "actor": {"id": "bom-agent", "actor_type": "Agent"},
          "causality": {"correlation_id": traj, "causation_id": None, "parent_id": None},
          "event": payload, "raw": None}
    requests.post(f"{admin}/api/adjudicate", json=ev, timeout=10)
send({"category": "Control", "payload": {"type": "Started", "data": {"agent_id": "bom-agent"}}})
send({"category": "Action", "payload": {"type": "ShellCommand", "data": {"call_id": "c1", "command": "git status", "working_dir": "/tmp"}}})
send({"category": "Action", "payload": {"type": "ShellCommand", "data": {"call_id": "c2", "command": "pip install requests", "working_dir": "/tmp"}}})
send({"category": "Action", "payload": {"type": "FileOperation", "data": {"call_id": "c3", "operation": "Read", "path": "README.md", "content": None}}})
send({"category": "Action", "payload": {"type": "WebFetch", "data": {"call_id": "c4", "url": "https://api.github.com/repos/x", "prompt": "fetch"}}})
send({"category": "Action", "payload": {"type": "ToolCall", "data": {"call_id": "c5", "tool": "search_docs", "arguments": {"q": "cedar"}}}})
print("sent 6 events")
PY

echo "== Read AgBOM: per-trajectory endpoint =="
kinds="$(curl -s "$ADMIN_URL/api/trajectories/$TRAJ/agbom" | "$PY" -c '
import sys, json
d = json.load(sys.stdin)
assert d.get("bomFormat") == "CycloneDX", d.get("bomFormat")
ks = set()
for c in d.get("components", []):
    for p in c.get("properties", []):
        if p["name"] == "sondera:component_kind":
            ks.add(p["value"])
print(",".join(sorted(ks)))
')"
assert_contains "agbom has the agent component"        "$kinds" "agent"
assert_contains "agbom detects shell capability"       "$kinds" "capability"
assert_contains "agbom detects package dependency"     "$kinds" "dependency"
assert_contains "agbom detects the API host"           "$kinds" "api"
assert_contains "agbom detects the tool"               "$kinds" "tool"
assert_contains "agbom detects a knowledge source"     "$kinds" "knowledge_source"

echo "== Read AgBOM: aggregate endpoint =="
comps="$(curl -s "$ADMIN_URL/api/agbom?agent_id=bom-agent" | "$PY" -c 'import sys,json;print(len(json.load(sys.stdin).get("components",[])))')"
[ "$comps" -ge 5 ] && pass "aggregate agbom returns components ($comps)" || fail "aggregate agbom too few: $comps"

echo "== Read AgBOM: sondera-claude CLI =="
cli="$("$CLAUDE_BIN" agbom show --admin-url "$ADMIN_URL" --trajectory-id "$TRAJ" 2>/dev/null | "$PY" -c 'import sys,json;d=json.load(sys.stdin);print(d.get("bomFormat"),d.get("serialNumber","")[:20])')"
assert_contains "CLI returns a CycloneDX doc" "$cli" "CycloneDX"
assert_contains "CLI serial is a sondera agbom urn" "$cli" "urn:sondera:agbom"

summary "agbom"
