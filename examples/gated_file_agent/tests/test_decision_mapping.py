"""Tool decision mapping with a mocked PolicyGate (no harness needed)."""

from __future__ import annotations

from typing import Any

import pytest

import gated_agent.mcp_file_server as srv
from sondera.gate import PolicyDecision


class FakeTrajectory:
    def __init__(self, decision: PolicyDecision) -> None:
        self._decision = decision

    def __enter__(self) -> "FakeTrajectory":
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    def check(self, action: Any) -> PolicyDecision:
        return self._decision


class FakeGate:
    def __init__(self, decision: PolicyDecision) -> None:
        self._decision = decision
        self.mandate_jwt = None

    def trajectory(self, **_: Any) -> FakeTrajectory:
        return FakeTrajectory(self._decision)

    def escalation_handle(self, decision: PolicyDecision) -> None:
        return None


def install_gate(monkeypatch: pytest.MonkeyPatch, decision: PolicyDecision) -> None:
    monkeypatch.setattr(srv, "GATE", FakeGate(decision))


def test_write_denied_does_not_touch_filesystem(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("GATED_AGENT_ROOT", str(tmp_path))
    deny = PolicyDecision(
        decision="Deny",
        reason="blocked",
        annotations=[{"policy_id": "forbid-source-write-secrets-python"}],
    )
    install_gate(monkeypatch, deny)

    result = srv.write_file("app.py", "SECRET = 'x'")
    assert result["status"] == "denied"
    assert result["decision"] == "Deny"
    assert "forbid-source-write-secrets-python" in result["policy_ids"]
    assert not (tmp_path / "app.py").exists()


def test_write_allowed_writes_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("GATED_AGENT_ROOT", str(tmp_path))
    allow = PolicyDecision(decision="Allow", annotations=[])
    install_gate(monkeypatch, allow)

    result = srv.write_file("ok.txt", "hello")
    assert result["status"] == "ok"
    assert (tmp_path / "ok.txt").read_text() == "hello"


def test_send_email_escalate_reports_pending(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("GATED_AGENT_ROOT", str(tmp_path))
    escalate = PolicyDecision(
        decision="Escalate",
        reason="needs approval",
        escalation_id="esc-1",
        annotations=[{"policy_id": "escalate-send-email-default"}],
    )
    install_gate(monkeypatch, escalate)

    result = srv.send_email("a@b.com", "hi", wait_for_operator=False)
    assert result["status"] == "pending_approval"
    assert result["decision"] == "Escalate"
