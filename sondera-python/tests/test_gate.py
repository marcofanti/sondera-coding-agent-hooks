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

def test_shell_action_event_shape():
    a = Action.shell("git", "status")
    ev = a.to_event()
    assert "Action" in ev
    assert "ShellCommand" in ev["Action"]
    assert ev["Action"]["ShellCommand"]["command"] == "git"
    assert ev["Action"]["ShellCommand"]["args"] == ["status"]


def test_read_file_action():
    a = Action.read_file("/tmp/data.csv")
    ev = a.to_event()
    assert ev["Action"]["FileOperation"]["operation"] == "Read"
    assert ev["Action"]["FileOperation"]["path"] == "/tmp/data.csv"


def test_write_file_action():
    a = Action.write_file("/tmp/out.txt", "hello")
    ev = a.to_event()
    assert ev["Action"]["FileOperation"]["operation"] == "Write"
    assert ev["Action"]["FileOperation"]["content"] == "hello"


def test_fetch_action():
    a = Action.fetch("https://api.github.com/repos/foo")
    ev = a.to_event()
    assert ev["Action"]["WebFetch"]["prompt"] == "fetch"


def test_navigate_action():
    a = Action.navigate("https://booking.com")
    ev = a.to_event()
    assert ev["Action"]["WebFetch"]["prompt"] == "navigate"


def test_submit_form_action():
    a = Action.submit_form("https://booking.com/checkout")
    ev = a.to_event()
    assert ev["Action"]["WebFetch"]["prompt"] == "submit_form"


def test_send_email_action():
    a = Action.send_email()
    ev = a.to_event()
    assert ev["Action"]["WebFetch"]["prompt"] == "send_email"


def test_tool_call_action():
    a = Action.tool_call("gmail_send", to="alice@example.com", body="hi")
    ev = a.to_event()
    assert ev["Action"]["ToolCall"]["tool"] == "gmail_send"
    assert ev["Action"]["ToolCall"]["arguments"]["to"] == "alice@example.com"


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
        assert body.get("raw") == JWT, f"raw field missing or wrong: {body.get('raw')!r}"
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
    assert "Observation" in body["event"]
    assert "FileOperationResult" in body["event"]["Observation"]


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
