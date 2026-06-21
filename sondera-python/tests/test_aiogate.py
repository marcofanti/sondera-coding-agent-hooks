"""Async gate tests — mocks adjudicate_raw / poll responses via AsyncMock."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from sondera import Action
from sondera.gate import PolicyDecision
from sondera.aiogate import AsyncPolicyGate, AsyncEscalationHandle

ADMIN_URL = "http://localhost:9090"


def make_decision(decision: str, reason: str = None, escalation_id: str = None) -> PolicyDecision:
    return PolicyDecision(decision=decision, reason=reason, escalation_id=escalation_id)


# ─── AsyncPolicyGate.adjudicate_raw (mocked at the method level) ─────────────

@pytest.mark.asyncio
async def test_async_gate_allow():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Allow"))
    ev = gate._build_event("agent", "python", "traj-1", Action.shell("ls"))
    d = await gate.adjudicate_raw(ev)
    assert d.allow


@pytest.mark.asyncio
async def test_async_gate_deny():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Deny", "rm -rf blocked"))
    ev = gate._build_event("agent", "python", "traj-1", Action.shell("rm", "-rf", "/"))
    d = await gate.adjudicate_raw(ev)
    assert d.deny
    assert "blocked" in (d.reason or "")


@pytest.mark.asyncio
async def test_async_gate_escalate_with_id():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(
        return_value=make_decision("Escalate", escalation_id="esc-abc-123")
    )
    ev = gate._build_event("agent", "python", "traj-1", Action.submit_form("https://booking.com"))
    d = await gate.adjudicate_raw(ev)
    assert d.escalate
    assert d.escalation_id == "esc-abc-123"


# ─── AsyncTrajectory.check ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_async_trajectory_check_allow():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Allow"))
    async with gate.trajectory(agent_id="hermes-1") as traj:
        d = await traj.check(Action.read_file("/tmp/data.csv"))
    assert d.allow


@pytest.mark.asyncio
async def test_async_trajectory_check_and_raise_deny():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Deny", "blocked"))
    async with gate.trajectory() as traj:
        with pytest.raises(PermissionError, match="Deny"):
            await traj.check_and_raise(Action.shell("rm", "-rf", "/"))


@pytest.mark.asyncio
async def test_async_trajectory_check_and_raise_passes_on_allow():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Allow"))
    async with gate.trajectory() as traj:
        d = await traj.check_and_raise(Action.shell("ls"))
    assert d.allow


# ─── AsyncEscalationHandle.wait ───────────────────────────────────────────────

def _make_poll_session(statuses: list[str]):
    """Build a mock aiohttp session that returns successive statuses."""
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)

    call_count = {"n": 0}
    statuses_copy = list(statuses)

    async def fake_poll(gate_ref, esc_id, poll_interval, timeout):
        for status in statuses_copy:
            if status == "approved":
                return PolicyDecision(decision="Allow", reason="operator approved")
            if status in ("denied", "timed_out"):
                return PolicyDecision(decision="Deny", reason=f"operator {status}")
            await asyncio.sleep(0)
        return PolicyDecision(decision="Deny", reason="escalation timed out")

    return fake_poll


def _mock_session_with_statuses(statuses: list[str]) -> MagicMock:
    """Build a fake aiohttp session whose get() returns async CMs with successive statuses."""
    call_idx = {"i": 0}

    def fake_get(url, **_kw):
        """Sync — aiohttp.ClientSession.get() is not a coroutine."""
        idx = call_idx["i"]
        call_idx["i"] += 1
        status = statuses[min(idx, len(statuses) - 1)]
        resp = MagicMock()
        resp.status = 200
        resp.raise_for_status = MagicMock()
        resp.json = AsyncMock(return_value={"id": "esc-xyz", "status": status})
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        return resp  # sync return — aiohttp async CM

    session = MagicMock()
    session.get = fake_get
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


@pytest.mark.asyncio
async def test_async_escalation_handle_approved():
    """Simulate poll: pending → approved."""
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    handle = AsyncEscalationHandle(escalation_id="esc-xyz", gate=gate)
    session = _mock_session_with_statuses(["pending", "approved"])
    with patch.object(gate, "_session", return_value=session):
        d = await handle.wait(poll_interval=0.01, timeout=5.0)
    assert d.allow
    assert d.reason == "operator approved"


@pytest.mark.asyncio
async def test_async_escalation_handle_denied():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    handle = AsyncEscalationHandle(escalation_id="esc-xyz", gate=gate)
    session = _mock_session_with_statuses(["denied"])
    with patch.object(gate, "_session", return_value=session):
        d = await handle.wait(poll_interval=0.01, timeout=5.0)
    assert d.deny


@pytest.mark.asyncio
async def test_async_escalation_handle_timeout():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    handle = AsyncEscalationHandle(escalation_id="esc-xyz", gate=gate)
    session = _mock_session_with_statuses(["pending"] * 30)
    with patch.object(gate, "_session", return_value=session):
        d = await handle.wait(poll_interval=0.01, timeout=0.05)
    assert d.deny
    assert "timed out" in (d.reason or "")


# ─── escalation_handle() helper ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_escalation_handle_helper_returns_async_handle():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    d = PolicyDecision(decision="Escalate", escalation_id="esc-42")
    h = gate.escalation_handle(d)
    assert isinstance(h, AsyncEscalationHandle)
    assert h.escalation_id == "esc-42"


@pytest.mark.asyncio
async def test_escalation_handle_helper_returns_none_on_allow():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    d = PolicyDecision(decision="Allow")
    assert gate.escalation_handle(d) is None


@pytest.mark.asyncio
async def test_escalation_handle_helper_returns_none_without_id():
    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    d = PolicyDecision(decision="Escalate")  # escalation_id=None
    assert gate.escalation_handle(d) is None


# ─── AsyncTrajectory.observe() ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_async_trajectory_observe_shell_output():
    """observe() sends a ShellCommandOutput event through adjudicate_raw."""
    from sondera import Observation

    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Allow"))

    async with gate.trajectory(agent_id="hermes-1") as traj:
        obs = Observation.shell_output(call_id="call-1", stdout="total 0\n", exit_code=0)
        d = await traj.observe(obs)

    assert d.allow
    call_args = gate.adjudicate_raw.call_args[0][0]
    event_body = call_args["event"]
    assert "Observation" in event_body
    assert "ShellCommandOutput" in event_body["Observation"]
    assert event_body["Observation"]["ShellCommandOutput"]["stdout"] == "total 0\n"


@pytest.mark.asyncio
async def test_async_trajectory_observe_prompt():
    """observe() with a Prompt observation sends the right event shape."""
    from sondera import Observation

    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Allow"))

    async with gate.trajectory() as traj:
        obs = Observation.prompt(content="summarise the file", role="user")
        d = await traj.observe(obs)

    assert d.allow
    event_body = gate.adjudicate_raw.call_args[0][0]["event"]
    assert "Observation" in event_body
    assert "Prompt" in event_body["Observation"]
    assert event_body["Observation"]["Prompt"]["content"] == "summarise the file"


@pytest.mark.asyncio
async def test_async_trajectory_observe_think():
    """observe() with a Think observation sends the right event shape."""
    from sondera import Observation

    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(return_value=make_decision("Allow"))

    async with gate.trajectory() as traj:
        obs = Observation.think(thought="I should check permissions first")
        d = await traj.observe(obs)

    assert d.allow
    event_body = gate.adjudicate_raw.call_args[0][0]["event"]
    assert "Observation" in event_body
    assert "Think" in event_body["Observation"]


@pytest.mark.asyncio
async def test_async_trajectory_observe_returns_deny():
    """observe() propagates Deny decisions from the harness."""
    from sondera import Observation

    gate = AsyncPolicyGate(admin_url=ADMIN_URL)
    gate.adjudicate_raw = AsyncMock(
        return_value=make_decision("Deny", "HighlyConfidential content detected")
    )

    async with gate.trajectory() as traj:
        obs = Observation.shell_output(
            call_id="call-2",
            stdout="AWS_SECRET_ACCESS_KEY=AKIA...",
            exit_code=0,
        )
        d = await traj.observe(obs)

    assert d.deny
    assert "HighlyConfidential" in (d.reason or "")
