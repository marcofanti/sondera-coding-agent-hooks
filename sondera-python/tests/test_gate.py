"""Unit tests for PolicyGate and Trajectory using mocked HTTP responses."""

import json
import uuid
import pytest
import responses as resp_lib

from sondera import PolicyGate, PolicyDecision, Action, Observation


ADMIN_URL = "http://localhost:9090"


def make_gate(**kw) -> PolicyGate:
    return PolicyGate(admin_url=ADMIN_URL, default_agent_id="test-agent", **kw)


def adj_response(decision: str, reason: str = None) -> dict:
    return {"decision": decision, "reason": reason, "annotations": []}


# ─── PolicyDecision ───────────────────────────────────────────────────────────

def test_decision_allow_is_truthy():
    d = PolicyDecision(decision="Allow")
    assert d.allow and not d.deny and not d.escalate


def test_decision_deny_is_falsy():
    d = PolicyDecision(decision="Deny")
    assert d.deny and not d.allow


def test_decision_escalate():
    d = PolicyDecision(decision="Escalate")
    assert d.escalate and not d.allow


# ─── Action helpers ───────────────────────────────────────────────────────────
#
# The harness deserializes events with adjacent tagging: the TrajectoryEvent
# enum is {"category": <variant>, "payload": {...}} and the inner Action enum is
# {"type": <variant>, "data": {...}}. `inner` unwraps both layers.

def inner(ev: dict) -> tuple[str, dict]:
    payload = ev["payload"]
    return payload["type"], payload["data"]


def test_shell_action_event_shape():
    a = Action.shell("git", "status")
    ev = a.to_event()
    assert ev["category"] == "Action"
    variant, data = inner(ev)
    assert variant == "ShellCommand"
    # Args fold into the command string — the Rust struct has no args field,
    # and guardrails must scan the full command line.
    assert data["command"] == "git status"
    assert data["call_id"].startswith("call-")


def test_delete_file_action():
    variant, data = inner(Action.delete_file("/tmp/old.pem").to_event())
    assert variant == "FileOperation"
    assert data["operation"] == "Delete"
    assert data["path"] == "/tmp/old.pem"


def test_read_file_action():
    variant, data = inner(Action.read_file("/tmp/data.csv").to_event())
    assert variant == "FileOperation"
    assert data["operation"] == "Read"
    assert data["path"] == "/tmp/data.csv"


def test_write_file_action():
    variant, data = inner(Action.write_file("/tmp/out.txt", "hello").to_event())
    assert data["operation"] == "Write"
    assert data["content"] == "hello"


def test_fetch_action():
    _, data = inner(Action.fetch("https://api.github.com/repos/foo").to_event())
    assert data["prompt"] == "fetch"


def test_navigate_action():
    _, data = inner(Action.navigate("https://booking.com").to_event())
    assert data["prompt"] == "navigate"


def test_submit_form_action():
    _, data = inner(Action.submit_form("https://booking.com/checkout").to_event())
    assert data["prompt"] == "submit_form"


def test_send_email_action():
    _, data = inner(Action.send_email().to_event())
    assert data["prompt"] == "send_email"


def test_tool_call_action():
    variant, data = inner(Action.tool_call("gmail_send", to="alice@example.com", body="hi").to_event())
    assert variant == "ToolCall"
    assert data["tool"] == "gmail_send"
    assert data["arguments"]["to"] == "alice@example.com"


# ─── PolicyGate.adjudicate_raw (mocked HTTP) ─────────────────────────────────

@resp_lib.activate
def test_gate_allow_response():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Allow"), status=200)

    gate = make_gate()
    traj_id = str(uuid.uuid4())
    event = gate._build_event("test-agent", "python", traj_id, Action.shell("ls"))
    decision = gate.adjudicate_raw(event)

    assert decision.allow


@resp_lib.activate
def test_gate_deny_response():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Deny", "rm -rf is forbidden"), status=200)

    gate = make_gate()
    traj_id = str(uuid.uuid4())
    event = gate._build_event("test-agent", "python", traj_id, Action.shell("rm", "-rf", "/"))
    decision = gate.adjudicate_raw(event)

    assert decision.deny
    assert "forbidden" in (decision.reason or "")


@resp_lib.activate
def test_gate_escalate_response():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Escalate"), status=200)

    gate = make_gate()
    traj_id = str(uuid.uuid4())
    event = gate._build_event("test-agent", "python", traj_id, Action.submit_form("https://example.com"))
    decision = gate.adjudicate_raw(event)

    assert decision.escalate


# ─── Trajectory.check ─────────────────────────────────────────────────────────

@resp_lib.activate
def test_trajectory_check_allow():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Allow"), status=200)

    gate = make_gate()
    with gate.trajectory(agent_id="hermes-1", provider_id="ollama") as traj:
        d = traj.check(Action.read_file("/tmp/data.csv"))
    assert d.allow


@resp_lib.activate
def test_trajectory_check_and_raise_allow():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Allow"), status=200)

    gate = make_gate()
    with gate.trajectory() as traj:
        d = traj.check_and_raise(Action.shell("cat", "/tmp/file"))
    assert d.allow


@resp_lib.activate
def test_trajectory_check_and_raise_deny_raises():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Deny", "shell blocked"), status=200)

    gate = make_gate()
    with gate.trajectory() as traj:
        with pytest.raises(PermissionError, match="Deny"):
            traj.check_and_raise(Action.shell("rm", "-rf", "/"))


# ─── Mandate JWT is forwarded as raw field ────────────────────────────────────

@resp_lib.activate
def test_mandate_jwt_forwarded():
    JWT = "eyJ.aGVsbG8.d29ybGQ"

    def callback(req):
        body = json.loads(req.body)
        # The mandate engine reads event.raw["mandate_jwt"] — the JWT must be
        # nested under that key, not sent as a bare string.
        assert body.get("raw") == {"mandate_jwt": JWT}, (
            f"raw field missing or wrong: {body.get('raw')!r}"
        )
        return (200, {}, json.dumps(adj_response("Allow")))

    resp_lib.add_callback(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate", callback,
                          content_type="application/json")

    gate = PolicyGate(admin_url=ADMIN_URL, mandate_jwt=JWT)
    with gate.trajectory() as traj:
        d = traj.check(Action.shell("ls"))
    assert d.allow


# ─── Observation support ──────────────────────────────────────────────────────

@resp_lib.activate
def test_trajectory_observe_sends_observation_event():
    """observe() must POST an Observation event (not an Action event)."""
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Allow"), status=200)

    gate = make_gate()
    with gate.trajectory() as traj:
        d = traj.observe(Observation.shell_output("hello world\n"))
    assert d.allow


@resp_lib.activate
def test_trajectory_observe_event_shape():
    """The event payload for an Observation must have the right structure."""
    captured = {}

    def callback(req):
        captured["body"] = json.loads(req.body)
        return (200, {}, json.dumps(adj_response("Allow")))

    resp_lib.add_callback(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate", callback,
                          content_type="application/json")
    gate = make_gate()
    with gate.trajectory(trajectory_id="traj-obs-test") as traj:
        traj.observe(Observation.file_result(content="secret key: abc123"))

    body = captured["body"]
    assert body["trajectory_id"] == "traj-obs-test"
    assert body["event"]["category"] == "Observation"
    assert body["event"]["payload"]["type"] == "FileOperationResult"


@resp_lib.activate
def test_trajectory_observe_prompt():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Allow"), status=200)
    gate = make_gate()
    with gate.trajectory() as traj:
        d = traj.observe(Observation.prompt("please read my secrets", role="user"))
    assert d.allow


@resp_lib.activate
def test_trajectory_observe_think():
    resp_lib.add(resp_lib.POST, f"{ADMIN_URL}/api/adjudicate",
                 json=adj_response("Allow"), status=200)
    gate = make_gate()
    with gate.trajectory() as traj:
        d = traj.observe(Observation.think("I should check the credentials file next"))
    assert d.allow
