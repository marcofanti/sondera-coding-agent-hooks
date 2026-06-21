"""PolicyGate — connects to the Sondera admin HTTP API and adjudicates events."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import requests

from .actions import ShellAction, FileReadAction, FileWriteAction, WebFetchAction, ToolCallAction


@dataclass
class PolicyDecision:
    decision: str   # "Allow" | "Deny" | "Escalate"
    reason: Optional[str] = None
    escalation_id: Optional[str] = None
    annotations: list[dict] = None

    @property
    def allow(self) -> bool:
        return self.decision == "Allow"

    @property
    def deny(self) -> bool:
        return self.decision == "Deny"

    @property
    def escalate(self) -> bool:
        return self.decision == "Escalate"

    @classmethod
    def _from_response(cls, data: dict) -> "PolicyDecision":
        return cls(
            decision=data.get("decision", "Deny"),
            reason=data.get("reason"),
            escalation_id=data.get("escalation_id"),
            annotations=data.get("annotations", []),
        )


@dataclass
class EscalationHandle:
    """Returned when a decision is Escalate — poll until approved or denied."""

    escalation_id: str
    gate: "PolicyGate"

    def wait(self, poll_interval: float = 2.0, timeout: float = 120.0) -> PolicyDecision:
        """Block until the operator approves or denies, or the TTL expires."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = requests.get(
                f"{self.gate.admin_url}/api/escalations/{self.escalation_id}",
                timeout=10,
            )
            if resp.status_code == 404:
                return PolicyDecision(decision="Deny", reason="escalation not found")
            resp.raise_for_status()
            record = resp.json()
            status = record.get("status", "pending")
            if status == "approved":
                return PolicyDecision(decision="Allow", reason="operator approved")
            if status in ("denied", "timed_out"):
                return PolicyDecision(decision="Deny", reason=f"operator {status}")
            time.sleep(poll_interval)
        return PolicyDecision(decision="Deny", reason="escalation timed out")

    def approve(self, decided_by: str = "sdk") -> bool:
        resp = requests.post(
            f"{self.gate.admin_url}/api/escalations/{self.escalation_id}/approve",
            json={"decided_by": decided_by},
            timeout=10,
        )
        return resp.ok

    def deny_action(self, decided_by: str = "sdk") -> bool:
        resp = requests.post(
            f"{self.gate.admin_url}/api/escalations/{self.escalation_id}/deny",
            json={"decided_by": decided_by},
            timeout=10,
        )
        return resp.ok


class PolicyGate:
    """Policy gate for Python-based AI agents.

    Args:
        admin_url: Base URL of the Sondera admin HTTP server (default: http://localhost:9090).
        mandate_jwt: Optional Ed25519 mandate JWT issued by the operator; included as the
            `mandate` context field in every adjudication request.
        default_agent_id: Agent ID used when no trajectory context manager is active.
        default_provider_id: Provider ID used when no trajectory context manager is active.
    """

    def __init__(
        self,
        admin_url: str = "http://localhost:9090",
        mandate_jwt: Optional[str] = None,
        default_agent_id: str = "python-agent",
        default_provider_id: str = "python",
    ) -> None:
        self.admin_url = admin_url.rstrip("/")
        self.mandate_jwt = mandate_jwt
        self.default_agent_id = default_agent_id
        self.default_provider_id = default_provider_id

    def trajectory(
        self,
        agent_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        trajectory_id: Optional[str] = None,
    ) -> "Trajectory":
        from .trajectory import Trajectory
        return Trajectory(
            gate=self,
            agent_id=agent_id or self.default_agent_id,
            provider_id=provider_id or self.default_provider_id,
            trajectory_id=trajectory_id or str(uuid.uuid4()),
        )

    def _build_event(
        self,
        agent_id: str,
        provider_id: str,
        trajectory_id: str,
        action: Any,
    ) -> dict:
        return {
            "event_id": str(uuid.uuid4()),
            "trajectory_id": trajectory_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent": {
                "id": agent_id,
                "provider_id": provider_id,
            },
            "actor": {
                "id": agent_id,
                "actor_type": "Agent",
            },
            "causality": {
                "correlation_id": trajectory_id,
                "causation_id": None,
                "parent_id": None,
            },
            "event": action.to_event(),
            "raw": self.mandate_jwt,
        }

    def adjudicate_raw(self, event: dict) -> PolicyDecision:
        resp = requests.post(
            f"{self.admin_url}/api/adjudicate",
            json=event,
            timeout=30,
        )
        resp.raise_for_status()
        return PolicyDecision._from_response(resp.json())

    def escalation_handle(self, decision: PolicyDecision) -> Optional["EscalationHandle"]:
        """Return an EscalationHandle if the decision is Escalate and an ID was surfaced."""
        if decision.escalate and decision.escalation_id:
            return EscalationHandle(
                escalation_id=decision.escalation_id,
                gate=self,
            )
        return None
