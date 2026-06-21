"""Trajectory context manager for grouping agent tool calls."""

from __future__ import annotations

import time
import uuid
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .gate import PolicyGate, PolicyDecision


class Trajectory:
    """Groups a sequence of tool calls under a shared trajectory ID.

    Use as a context manager::

        with gate.trajectory(agent_id="my-agent", provider_id="langchain") as traj:
            decision = traj.check(Action.shell("ls /tmp"))
            if decision.allow:
                ...
    """

    def __init__(
        self,
        gate: "PolicyGate",
        agent_id: str,
        provider_id: str,
        trajectory_id: str,
    ) -> None:
        self.gate = gate
        self.agent_id = agent_id
        self.provider_id = provider_id
        self.trajectory_id = trajectory_id

    def __enter__(self) -> "Trajectory":
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    def check(self, action: Any) -> "PolicyDecision":
        """Adjudicate an action. Returns a `PolicyDecision`."""
        event = self.gate._build_event(
            agent_id=self.agent_id,
            provider_id=self.provider_id,
            trajectory_id=self.trajectory_id,
            action=action,
        )
        return self.gate.adjudicate_raw(event)

    def check_and_raise(self, action: Any) -> "PolicyDecision":
        """Adjudicate an action; raise `PermissionError` if not allowed."""
        decision = self.check(action)
        if not decision.allow:
            raise PermissionError(
                f"Sondera denied {action.__class__.__name__}: "
                f"{decision.decision} — {decision.reason}"
            )
        return decision

    def observe(self, observation: Any) -> "PolicyDecision":
        """Send a tool observation back to the harness for sensitivity classification.

        The harness may taint the trajectory when the output contains sensitive data
        (private keys, credentials, confidential PII, etc.).  The returned decision
        indicates whether the harness accepted the observation.

        Usage::

            from sondera import Observation

            with gate.trajectory() as traj:
                decision = traj.check(Action.shell("cat secrets.txt"))
                if decision.allow:
                    output = run("cat secrets.txt")
                    traj.observe(Observation.shell_output(output))
        """
        event = {
            "event_id": str(uuid.uuid4()),
            "trajectory_id": self.trajectory_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent": {"id": self.agent_id, "provider_id": self.provider_id},
            "actor": {"id": self.agent_id, "actor_type": "Agent"},
            "causality": {
                "correlation_id": self.trajectory_id,
                "causation_id": None,
                "parent_id": None,
            },
            "event": observation.to_event(),
            "raw": self.gate.mandate_jwt,
        }
        return self.gate.adjudicate_raw(event)
